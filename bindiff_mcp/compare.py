"""Orchestration behind the MCP tools: export with IDA, diff with BinDiff.

A tool call is validated here and becomes a job (see ``bindiff_mcp.jobs``),
which runs the exports, the differ and the result files on a worker thread.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import subprocess
import tempfile
import threading
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

import bindiff.bindiff as bindiff_module
from bindiff import BinDiff
from bindiff.types import BindiffNotFound

from bindiff_mcp.errors import DiffError, ExportError, TimeLimitError
from bindiff_mcp.export import ExportResult, export_binary, resolve_binary
from bindiff_mcp.files import sha256_file
from bindiff_mcp.jobs import JobContext, JobRequest
from bindiff_mcp.limits import Deadline
from bindiff_mcp.reader import Program, read_diff, read_program
from bindiff_mcp.results import collect_results, program_metadata, write_results

#: The two binaries are exported into separate directories so that diffing two
#: builds of the same file name cannot overwrite one another's BinExport.
PRIMARY_DIR = "primary"
SECONDARY_DIR = "secondary"

_BINDIFF_MISSING = (
    "the bindiff executable was not found; install BinDiff and make `bindiff` "
    "reachable through PATH or the BINDIFF_PATH environment variable"
)

#: Longest differ output kept in an error message.
_OUTPUT_EXCERPT_CHARS = 2000


def export_request(binary: str, output_results_dir: str) -> JobRequest:
    """Validate a ``binexport`` call and describe the job that answers it."""
    binary_path = resolve_binary(binary)
    directory = _output_directory(output_results_dir)

    def work(context: JobContext) -> dict[str, Any]:
        context.stage("exporting")
        result = export_binary(
            binary_path,
            directory,
            deadline=context.deadline,
            progress=context.export_progress("binary"),
        )
        context.stage("reading the export")
        program = _open_program(result.binexport)
        return {**_export_fields(result), **program_metadata(program)}

    return JobRequest(
        tool="binexport",
        key=_request_key("binexport", directory, binary_path),
        arguments={"binary": str(binary_path), "output_results_dir": str(directory)},
        work=work,
    )


def compare_request(
    primary_binary: str,
    secondary_binary: str,
    output_results_dir: str,
) -> JobRequest:
    """Validate a ``bindiff_compare`` call and describe the job that answers it."""
    primary_path = resolve_binary(primary_binary)
    secondary_path = resolve_binary(secondary_binary)
    directory = _output_directory(output_results_dir)
    # Fail before spending minutes on autoanalysis if the differ is missing.
    differ = _differ_path()

    def work(context: JobContext) -> dict[str, Any]:
        context.stage("exporting")
        primary, secondary = _in_parallel(
            lambda: export_binary(
                primary_path,
                directory / PRIMARY_DIR,
                deadline=context.deadline,
                progress=context.export_progress("primary"),
            ),
            lambda: export_binary(
                secondary_path,
                directory / SECONDARY_DIR,
                deadline=context.deadline,
                progress=context.export_progress("secondary"),
            ),
        )
        context.stage("diffing")
        diff_file = _run_differ(differ, primary, secondary, directory, context.deadline)
        context.stage("writing results")
        return _diff_results(primary, secondary, diff_file, directory)

    return JobRequest(
        tool="bindiff_compare",
        key=_request_key("bindiff_compare", directory, primary_path, secondary_path),
        arguments={
            "primary_binary": str(primary_path),
            "secondary_binary": str(secondary_path),
            "output_results_dir": str(directory),
        },
        work=work,
    )


def _output_directory(output_results_dir: str) -> Path:
    directory = Path(output_results_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise DiffError(
            f"cannot create output directory {directory}: {error}"
        ) from error
    return directory.resolve()


def _request_key(tool: str, directory: Path, *binaries: Path) -> str:
    """Requests are identical when tool, output directory and binary bytes match."""
    digests = []
    for binary in binaries:
        try:
            digests.append(sha256_file(binary))
        except OSError as error:
            raise ExportError(f"cannot read {binary}: {error}") from error
    return json.dumps([tool, str(directory), *digests])


def _differ_path() -> str:
    try:
        BinDiff.assert_installation_ok()
    except BindiffNotFound as error:
        raise DiffError(_BINDIFF_MISSING) from error
    # assert_installation_ok() records the executable it found here.
    return str(bindiff_module.BINDIFF_BINARY)


def _in_parallel(
    first: Callable[[], ExportResult], second: Callable[[], ExportResult]
) -> tuple[ExportResult, ExportResult]:
    """Run both exports at once and return both results.

    A failure is raised only once both have ended, so a job never finishes
    while an IDA worker it started is still running.
    """
    outcome: dict[str, Any] = {}

    def run_second() -> None:
        try:
            outcome["result"] = second()
        except Exception as error:  # noqa: BLE001 -- re-raised on the calling thread
            outcome["error"] = error

    # A daemon thread, like the job workers, so a stopping server is not held.
    helper = threading.Thread(target=run_second, name="bindiff-mcp-export", daemon=True)
    helper.start()
    try:
        first_result = first()
    finally:
        helper.join()
    if "error" in outcome:
        raise outcome["error"]
    return first_result, outcome["result"]


def _open_program(binexport: Path) -> Program:
    try:
        return read_program(binexport)
    except Exception as error:  # protobuf parsing raises broadly
        raise ExportError(f"cannot read BinExport file {binexport}: {error}") from error


def _export_fields(result: ExportResult) -> dict[str, Any]:
    return {
        "binary": str(result.binary),
        "binexport": str(result.binexport),
        "reused": result.reused,
    }


def _run_differ(
    differ: str,
    primary: ExportResult,
    secondary: ExportResult,
    directory: Path,
    deadline: Deadline,
) -> Path:
    """Diff the two exports into ``<directory>/<primary>_vs_<secondary>.BinDiff``."""
    diff_file = directory / f"{primary.binary.name}_vs_{secondary.binary.name}.BinDiff"
    remaining = deadline.remaining("diffing")
    # The differ writes into a scratch directory beside the result, so the
    # finished database is renamed into place and never seen half-written.
    with tempfile.TemporaryDirectory(prefix=".bindiff-", dir=directory) as scratch:
        try:
            completed = subprocess.run(
                [
                    differ,
                    f"--primary={primary.binexport}",
                    f"--secondary={secondary.binexport}",
                    f"--output_dir={scratch}",
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=remaining if math.isfinite(remaining) else None,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TimeLimitError(
                f"bindiff did not finish within {error.timeout:.1f} s"
            ) from error
        except OSError as error:
            raise DiffError(f"cannot run {differ}: {error}") from error
        produced = sorted(Path(scratch).glob("*.BinDiff"))
        if completed.returncode != 0 or not produced:
            raise DiffError(
                f"bindiff could not diff {primary.binexport.name} against "
                f"{secondary.binexport.name} (exit status {completed.returncode})"
                f"{_output_excerpt(completed)}"
            )
        _link_exports(produced[0], directory, primary.binexport, secondary.binexport)
        os.replace(produced[0], diff_file)
    return diff_file


def _output_excerpt(completed: subprocess.CompletedProcess[str]) -> str:
    output = (completed.stderr or completed.stdout or "").strip()
    return f"\n{output[-_OUTPUT_EXCERPT_CHARS:]}" if output else ""


def _link_exports(database: Path, base: Path, primary: Path, secondary: Path) -> None:
    """Record the exports relative to ``base``, where the BinDiff UI looks for them."""
    try:
        with closing(sqlite3.connect(database)) as connection:
            for file_id, export in ((1, primary), (2, secondary)):
                connection.execute(
                    "UPDATE file SET filename = ? WHERE id = ?",
                    (os.path.relpath(export.with_suffix(""), base), file_id),
                )
            connection.commit()
    except sqlite3.Error as error:
        raise DiffError(f"cannot update {database.name}: {error}") from error


def _diff_results(
    primary: ExportResult, secondary: ExportResult, diff_file: Path, directory: Path
) -> dict[str, Any]:
    try:
        diff = read_diff(diff_file)
    except Exception as error:  # sqlite raises broadly
        raise DiffError(f"cannot read {diff_file.name}: {error}") from error
    primary_program = _open_program(primary.binexport)
    secondary_program = _open_program(secondary.binexport)

    results = write_results(
        collect_results(diff, primary_program, secondary_program), directory
    )
    return {
        "primary": {**_export_fields(primary), **program_metadata(primary_program)},
        "secondary": {
            **_export_fields(secondary),
            **program_metadata(secondary_program),
        },
        "diff_file": str(diff_file),
        "similarity": diff.similarity,
        "confidence": diff.confidence,
        **results,
    }
