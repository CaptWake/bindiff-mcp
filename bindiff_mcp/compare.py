"""Orchestration behind the MCP tools: export with IDA, diff with BinDiff.

A tool call is validated here and becomes a job (see ``bindiff_mcp.jobs``),
which runs the exports, the differ and the result files on a worker thread.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bindiff import BinDiff
from bindiff.types import BindiffNotFound
from binexport import ProgramBinExport

from bindiff_mcp.errors import DiffError, ExportError
from bindiff_mcp.export import ExportResult, export_binary, resolve_binary
from bindiff_mcp.files import sha256_file
from bindiff_mcp.jobs import JobContext, JobRequest
from bindiff_mcp.results import program_metadata, write_results

#: The two binaries are exported into separate directories so that diffing two
#: builds of the same file name cannot overwrite one another's BinExport.
PRIMARY_DIR = "primary"
SECONDARY_DIR = "secondary"

_BINDIFF_MISSING = (
    "the bindiff executable was not found; install BinDiff and make `bindiff` "
    "reachable through PATH or the BINDIFF_PATH environment variable"
)


def export_request(binary: str, output_results_dir: str) -> JobRequest:
    """Validate a ``binexport`` call and describe the job that answers it."""
    binary_path = resolve_binary(binary)
    directory = _output_directory(output_results_dir)

    def work(context: JobContext) -> dict[str, Any]:
        context.stage("exporting")
        result = export_binary(
            binary_path, directory, progress=context.export_progress("binary")
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
    _assert_bindiff_installed()

    def work(context: JobContext) -> dict[str, Any]:
        context.stage("exporting")
        primary, secondary = _in_parallel(
            lambda: export_binary(
                primary_path,
                directory / PRIMARY_DIR,
                progress=context.export_progress("primary"),
            ),
            lambda: export_binary(
                secondary_path,
                directory / SECONDARY_DIR,
                progress=context.export_progress("secondary"),
            ),
        )
        context.stage("diffing")
        return _diff(primary, secondary, directory)

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


def _assert_bindiff_installed() -> None:
    try:
        BinDiff.assert_installation_ok()
    except BindiffNotFound as error:
        raise DiffError(_BINDIFF_MISSING) from error


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


def _open_program(binexport: Path) -> ProgramBinExport:
    try:
        return ProgramBinExport.open(binexport)
    except Exception as error:  # protobuf parsing raises broadly
        raise ExportError(f"cannot read BinExport file {binexport}: {error}") from error


def _export_fields(result: ExportResult) -> dict[str, Any]:
    return {
        "binary": str(result.binary),
        "binexport": str(result.binexport),
        "reused": result.reused,
    }


def _diff(
    primary: ExportResult, secondary: ExportResult, directory: Path
) -> dict[str, Any]:
    diff_file = directory / f"{primary.binary.name}_vs_{secondary.binary.name}.BinDiff"
    try:
        diff = BinDiff.from_binexport_files(
            str(primary.binexport),
            str(secondary.binexport),
            diff_file,
            override=True,
        )
    except Exception as error:  # the differ and sqlite raise broadly
        raise DiffError(f"bindiff failed: {error}") from error
    if diff is None:
        raise DiffError(
            f"bindiff could not diff {primary.binexport.name} against "
            f"{secondary.binexport.name}; see the bindiff output for details"
        )

    results = write_results(diff, directory)
    return {
        "primary": {**_export_fields(primary), **program_metadata(diff.primary)},
        "secondary": {**_export_fields(secondary), **program_metadata(diff.secondary)},
        "diff_file": str(diff_file),
        "similarity": diff.similarity,
        "confidence": diff.confidence,
        **results,
    }
