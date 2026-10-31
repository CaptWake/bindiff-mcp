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
import signal
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any

from ida_nexus import (
    DatabaseManager,
    NexusError,
    PythonExecutionResult,
    probe_database_state,
)

from bindiff_mcp.errors import ExportError, TimeLimitError
from bindiff_mcp.files import sha256_file, staging_path
from bindiff_mcp.limits import (
    ANALYSIS_TIMEOUT_SECONDS,
    EXPORT_TIMEOUT_SECONDS,
    OPEN_TIMEOUT_SECONDS,
    UNLIMITED,
    Deadline,
)
from bindiff_mcp.reader import exported_binary_sha256

#: Extension of the files produced by the BinExport IDA plugin.
BINEXPORT_SUFFIX = ".BinExport"

#: Plugin names tried when the IDC extension is not registered in the session.
PLUGIN_NAMES = ("binexport12_ida", "binexport11_ida")

#: Operation label shown in the Nexus worker logs for this server's requests.
OPERATION_LABEL = "bindiff-mcp"

#: Longest IDC/IDAPython output kept in an error message.
_LOG_EXCERPT_CHARS = 2000

#: How long a worker gets to exit after each step of ``_stop_worker``.
_WORKER_EXIT_SECONDS = 10.0

#: The idalib worker process behind each open database, by instance id.
_WORKER_PIDS: dict[str, int] = {}


def _record_worker(event: str, fields: dict[str, Any]) -> None:
    target = fields.get("target")
    if (
        event == "database_opened"
        and isinstance(target, dict)
        and target.get("backend") == "idalib"
        and isinstance(target.get("pid"), int)
    ):
        _WORKER_PIDS[str(fields["instance_id"])] = target["pid"]


DATABASE_MANAGER = DatabaseManager(
    open_timeout=OPEN_TIMEOUT_SECONDS,
    execute_timeout=EXPORT_TIMEOUT_SECONDS,
    on_event=_record_worker,
)

#: One lock per binary and per BinExport path; see ``export_binary``.
_PATH_LOCKS: dict[Path, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _ignore_progress(_state: str) -> None:
    """Progress sink for exports that run outside a job."""


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
    deadline: Deadline = UNLIMITED,
    progress: Callable[[str], None] = _ignore_progress,
) -> ExportResult:
    """Export ``binary`` to ``<output_dir>/<binary name>.BinExport``.

    An export made from the same bytes (it records their SHA-256) is reused
    unless ``override`` is set; file dates prove nothing, as installers and
    archives keep the original ones. A binary is exported by one caller at a
    time, and a caller that had to wait reuses the export it waited for: IDA
    Nexus hands every caller the same database for a path, and the first one to
    finish would close it under the others.
    """

    binary_path = resolve_binary(binary)
    try:
        digest = sha256_file(binary_path)
    except OSError as error:
        raise ExportError(f"cannot read {binary_path}: {error}") from error
    directory = Path(output_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ExportError(
            f"cannot create output directory {directory}: {error}"
        ) from error
    target = directory.resolve() / (binary_path.name + BINEXPORT_SUFFIX)

    with _exclusively(binary_path, target, deadline, progress):
        if not override and exported_binary_sha256(target) == digest:
            progress("reused")
            return ExportResult(binary=binary_path, binexport=target, reused=True)

        # A stale export must not survive a failed run and be mistaken for fresh.
        with suppress(OSError):
            target.unlink(missing_ok=True)

        _run_export(binary_path, target, deadline=deadline, progress=progress)
    progress("done")
    return ExportResult(binary=binary_path, binexport=target, reused=False)


def resolve_binary(binary: str | Path) -> Path:
    path = Path(binary).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ExportError(f"binary not found: {path}") from error
    if not resolved.is_file():
        raise ExportError(f"not a file: {resolved}")
    return resolved


@contextmanager
def _exclusively(
    binary: Path, target: Path, deadline: Deadline, progress: Callable[[str], None]
) -> Generator[None, None, None]:
    """Hold the locks of ``binary`` and ``target``, always taken in path order."""
    held: list[threading.Lock] = []
    try:
        for path in sorted({binary, target}):
            with _PATH_LOCKS_GUARD:
                lock = _PATH_LOCKS.setdefault(path, threading.Lock())
            if not lock.acquire(blocking=False):
                stage = f"waiting for another export of {binary.name}"
                progress(stage)
                timeout = deadline.remaining(stage)
                if not lock.acquire(timeout=timeout if math.isfinite(timeout) else -1):
                    raise TimeLimitError(
                        f"the job reached its {deadline.seconds:g} s limit while "
                        f"another job was still exporting {binary.name}"
                    )
            held.append(lock)
        yield
    finally:
        for lock in reversed(held):
            lock.release()


@contextmanager
def _time_limit(stage: str, timeout: float) -> Generator[None, None, None]:
    """Report a Nexus failure at ``timeout`` as ``stage`` running out of time."""
    started = time.monotonic()
    try:
        yield
    except NexusError as error:
        if time.monotonic() - started >= timeout:
            raise TimeLimitError(
                f"{stage} did not finish within {timeout:.1f} s"
            ) from error
        raise


def _run_export(
    binary: Path,
    target: Path,
    *,
    deadline: Deadline = UNLIMITED,
    progress: Callable[[str], None] = _ignore_progress,
) -> None:
    # IDA writes a staging file that is renamed into place, so an export that
    # is killed midway never leaves a truncated file that looks current.
    staging = staging_path(target)
    code = _EXPORT_TEMPLATE.substitute(
        output=json.dumps(str(staging)),
        plugins=json.dumps(list(PLUGIN_NAMES)),
    )
    progress("opening")
    deadline.remaining(f"opening {binary.name}")
    try:
        opened = DATABASE_MANAGER.open_database(str(binary), set_current=False)
    except (NexusError, OSError, ValueError) as error:
        raise ExportError(f"IDA could not open {binary.name}: {error}") from error

    instance_id = opened["instance_id"]
    timed_out = False
    try:
        progress("autoanalysis")
        stage = f"autoanalysis of {binary.name}"
        timeout = deadline.limit(stage, ANALYSIS_TIMEOUT_SECONDS)
        with _time_limit(stage, timeout):
            analysis = DATABASE_MANAGER.wait_autoanalysis(instance_id, timeout)
        if not analysis["complete"]:
            raise ExportError(f"{stage} stopped early ({analysis['status']})")

        progress("exporting")
        stage = f"BinExport of {binary.name}"
        timeout = deadline.limit(stage, EXPORT_TIMEOUT_SECONDS)
        with _time_limit(stage, timeout):
            execution = DATABASE_MANAGER.execute_python(
                code,
                instance_id,
                timeout=timeout,
                operation_label=OPERATION_LABEL,
                filename="<bindiff-mcp:binexport>",
            )
    except (NexusError, ValueError) as error:
        raise ExportError(f"BinExport failed for {binary.name}: {error}") from error
    except TimeLimitError:
        timed_out = True
        raise
    finally:
        # The lease is per-export: releasing it lets the idalib worker exit
        # instead of holding the database for the rest of the session.
        with suppress(Exception):
            DATABASE_MANAGER.close_database(instance_id)
        worker = _WORKER_PIDS.pop(instance_id, None)
        if timed_out and worker is not None:
            _stop_worker(worker, binary)

    try:
        _check_export(binary, staging, execution)
        os.replace(staging, target)
    finally:
        with suppress(OSError):
            staging.unlink(missing_ok=True)


def _stop_worker(pid: int, binary: Path) -> None:
    """Make sure the worker of a stage that ran out of time is gone.

    IDA cannot interrupt autoanalysis or an export underway, and a worker whose
    lease is released in the middle of one never shuts down. It is killed rather
    than asked to save: packing can outlast any grace period, and a kill leaves
    the packed database untouched. Only children of this process are stopped,
    never a GUI instance or another client's worker.
    """
    if _exited(pid):
        return
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    if not _exited(pid):
        return
    # Nexus would repair the half-analyzed leftovers into a database whose
    # functions differ from a full analysis. Without them the next open starts
    # over from the binary, or from the database last packed.
    state = probe_database_state(binary)
    if state["state"] == "crashed":
        for component in state["unpacked_files"]:
            with suppress(OSError):
                Path(component).unlink()


def _exited(pid: int) -> bool:
    """Wait up to ``_WORKER_EXIT_SECONDS`` for child ``pid`` to be gone."""
    deadline = time.monotonic() + _WORKER_EXIT_SECONDS
    while _child_state(pid) not in (None, "Z"):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)
    return True


def _child_state(pid: int) -> str | None:
    """Process state of ``pid`` if it is a child of this process, else ``None``."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    # The command name in parentheses may contain spaces; state and ppid follow.
    state, parent = stat[stat.rindex(")") + 2 :].split()[:2]
    return state if int(parent) == os.getpid() else None


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
