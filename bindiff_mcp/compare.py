"""Orchestration behind the MCP tools: export with IDA, diff with BinDiff."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from bindiff import BinDiff
from bindiff.types import BindiffNotFound
from binexport import ProgramBinExport

from bindiff_mcp.errors import DiffError, ExportError
from bindiff_mcp.export import ExportResult, export_binary
from bindiff_mcp.results import program_metadata, write_results

#: The two binaries are exported into separate directories so that diffing two
#: builds of the same file name cannot overwrite one another's BinExport.
PRIMARY_DIR = "primary"
SECONDARY_DIR = "secondary"

_BINDIFF_MISSING = (
    "the bindiff executable was not found; install BinDiff and make `bindiff` "
    "reachable through PATH or the BINDIFF_PATH environment variable"
)


async def run_export(binary: str, output_results_dir: str) -> dict[str, Any]:
    """Export one binary and report the BinExport file it produced."""
    result = await asyncio.to_thread(export_binary, binary, output_results_dir)
    program = await asyncio.to_thread(_open_program, result.binexport)
    return {**_export_fields(result), **program_metadata(program)}


async def run_compare(
    primary_binary: str,
    secondary_binary: str,
    output_results_dir: str,
) -> dict[str, Any]:
    """Export both binaries, diff them, and write the four result files."""
    directory = _output_directory(output_results_dir)
    # Fail before spending minutes on autoanalysis if the differ is missing.
    _assert_bindiff_installed()

    primary, secondary = await asyncio.gather(
        asyncio.to_thread(export_binary, primary_binary, directory / PRIMARY_DIR),
        asyncio.to_thread(export_binary, secondary_binary, directory / SECONDARY_DIR),
    )
    return await asyncio.to_thread(_diff, primary, secondary, directory)


def _output_directory(output_results_dir: str) -> Path:
    directory = Path(output_results_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise DiffError(
            f"cannot create output directory {directory}: {error}"
        ) from error
    return directory.resolve()


def _assert_bindiff_installed() -> None:
    try:
        BinDiff.assert_installation_ok()
    except BindiffNotFound as error:
        raise DiffError(_BINDIFF_MISSING) from error


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
