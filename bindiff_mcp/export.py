"""BinExport generation driven through IDA Nexus.

The BinExport IDA plugin registers the ``BinExportBinary(path)`` IDC function
when it initializes. Instead of spawning ``idat`` directly (what
``binexport.ProgramBinExport.generate`` does), the export runs inside the IDA
Nexus session that already owns the database: an existing IDA GUI instance when
the binary is open there, otherwise a headless idalib worker.
"""

from __future__ import annotations

import json
import math
import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any

from ida_nexus import DatabaseManager, NexusError, PythonExecutionResult

from bindiff_mcp.errors import ExportError

#: Extension of the files produced by the BinExport IDA plugin.
BINEXPORT_SUFFIX = ".BinExport"

#: Plugin names tried when the IDC extension is not registered in the session.
PLUGIN_NAMES = ("binexport12_ida", "binexport11_ida")

#: Operation label shown in the Nexus worker logs for this server's requests.
OPERATION_LABEL = "bindiff-mcp"

#: Longest IDC/IDAPython output kept in an error message.
_LOG_EXCERPT_CHARS = 2000


def _timeout_from_environment(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        timeout = float(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return timeout


#: Attaching to a GUI instance is immediate; spawning an idalib worker is not.
OPEN_TIMEOUT_SECONDS = _timeout_from_environment("BINDIFF_MCP_OPEN_TIMEOUT", 600.0)

#: Autoanalysis is awaited separately, so this only covers the export itself.
EXPORT_TIMEOUT_SECONDS = _timeout_from_environment("BINDIFF_MCP_EXPORT_TIMEOUT", 1800.0)

DATABASE_MANAGER = DatabaseManager(
    open_timeout=OPEN_TIMEOUT_SECONDS,
    execute_timeout=EXPORT_TIMEOUT_SECONDS,
)

# Runs in the IDA process. ``json.dumps`` builds the IDC string literal so paths
# containing backslashes or quotes survive the IDC parser. The trailing dict is
# the value Nexus returns to this process.
_EXPORT_TEMPLATE = Template(
    """
import json
import os

import ida_auto
import ida_loader
import idc

_output = $output
_plugins = $plugins
_loaded = []


def _export():
    return idc.eval_idc("BinExportBinary(" + json.dumps(_output) + ")")


def _failed(value):
    return isinstance(value, str) and value.startswith("IDC_FAILURE")


ida_auto.auto_wait()
_result = _export()
if _failed(_result):
    # The plugin is PLUGIN_FIX and normally registers BinExportBinary at
    # startup; load it explicitly when this session started without it.
    for _name in _plugins:
        if ida_loader.load_plugin(_name) is None:
            continue
        _loaded.append(_name)
        _result = _export()
        if not _failed(_result):
            break

{
    "idc_result": _result,
    "plugins_loaded": _loaded,
    "exists": os.path.isfile(_output),
    "size": os.path.getsize(_output) if os.path.isfile(_output) else 0,
}
"""
)


@dataclass(frozen=True, slots=True)
class ExportResult:
    """One binary exported to (or already present as) a BinExport file."""

    binary: Path
    binexport: Path
    reused: bool


def export_binary(
    binary: str | Path,
    output_dir: str | Path,
    *,
    override: bool = False,
) -> ExportResult:
    """Export ``binary`` to ``<output_dir>/<binary name>.BinExport``.

    An export that is at least as new as the binary is reused unless
    ``override`` is set, mirroring ``ProgramBinExport.generate``.
    """

    binary_path = _resolve_binary(binary)
    directory = Path(output_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ExportError(
            f"cannot create output directory {directory}: {error}"
        ) from error
    target = directory.resolve() / (binary_path.name + BINEXPORT_SUFFIX)

    if not override and _is_current(target, binary_path):
        return ExportResult(binary=binary_path, binexport=target, reused=True)

    # A stale export must not survive a failed run and be mistaken for fresh.
    with suppress(OSError):
        target.unlink(missing_ok=True)

    _run_export(binary_path, target)
    return ExportResult(binary=binary_path, binexport=target, reused=False)


def _resolve_binary(binary: str | Path) -> Path:
    path = Path(binary).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ExportError(f"binary not found: {path}") from error
    if not resolved.is_file():
        raise ExportError(f"not a file: {resolved}")
    return resolved


def _is_current(target: Path, binary: Path) -> bool:
    """Report whether ``target`` is an export of the current ``binary`` bytes."""
    try:
        return target.stat().st_mtime >= binary.stat().st_mtime
    except OSError:
        return False


def _run_export(binary: Path, target: Path) -> None:
    code = _EXPORT_TEMPLATE.substitute(
        output=json.dumps(str(target)),
        plugins=json.dumps(list(PLUGIN_NAMES)),
    )
    try:
        opened = DATABASE_MANAGER.open_database(str(binary), set_current=False)
    except (NexusError, OSError, ValueError) as error:
        raise ExportError(f"IDA could not open {binary.name}: {error}") from error

    instance_id = opened["instance_id"]
    try:
        DATABASE_MANAGER.ensure_autoanalysis(instance_id)
        execution = DATABASE_MANAGER.execute_python(
            code,
            instance_id,
            timeout=EXPORT_TIMEOUT_SECONDS,
            operation_label=OPERATION_LABEL,
            filename="<bindiff-mcp:binexport>",
        )
    except (NexusError, ValueError) as error:
        raise ExportError(f"BinExport failed for {binary.name}: {error}") from error
    finally:
        # The lease is per-export: releasing it lets the idalib worker exit
        # instead of holding the database for the rest of the session.
        with suppress(Exception):
            DATABASE_MANAGER.close_database(instance_id)

    _check_export(binary, target, execution)


def _check_export(binary: Path, target: Path, execution: PythonExecutionResult) -> None:
    outcome: Any = execution["result"]
    if not isinstance(outcome, dict):
        raise ExportError(
            f"BinExport returned an unexpected result for {binary.name}: "
            f"{outcome!r}{_logs(execution)}"
        )

    status = outcome.get("idc_result")
    if isinstance(status, str):
        hint = ""
        if not outcome.get("plugins_loaded"):
            hint = (
                " The BinExport IDA plugin was not found; install "
                f"{PLUGIN_NAMES[0]}.so into $IDAUSR/plugins."
            )
        raise ExportError(f"BinExportBinary failed for {binary.name}: {status}.{hint}")

    if not outcome.get("exists") or not target.is_file():
        raise ExportError(
            f"BinExport wrote no file for {binary.name} at {target}"
            f" (IDC result: {status!r}){_logs(execution)}"
        )
    if not outcome.get("size"):
        raise ExportError(
            f"BinExport wrote an empty file for {binary.name} at {target}"
        )
    # BinExportBinary reports eOk (0) through the IDC error code and leaves the
    # IDC return value unset, so a missing value is success too.
    if isinstance(status, int) and status != 0:
        raise ExportError(
            f"BinExportBinary reported error {status} for {binary.name}{_logs(execution)}"
        )


def _logs(execution: PythonExecutionResult) -> str:
    streams = "".join(
        f"\n{name}: {text.strip()[-_LOG_EXCERPT_CHARS:]}"
        for name, text in (
            ("stdout", execution["stdout"]),
            ("stderr", execution["stderr"]),
        )
        if text.strip()
    )
    return streams
