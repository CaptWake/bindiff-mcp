"""Export reuse and locking, IDA worker snippet, time limits, failure reporting."""

from __future__ import annotations

import ast
import json
import os
import signal
import subprocess
import sys
import threading
import time
import types
from contextlib import suppress
from pathlib import Path

import pytest
from ida_nexus.errors import RemoteError

from bindiff_mcp.errors import ExportError, TimeLimitError
from bindiff_mcp.export import (
    _EXPORT_TEMPLATE,
    PLUGIN_NAMES,
    ExportResult,
    _check_export,
    _stop_worker,
    export_binary,
)
from bindiff_mcp.limits import Deadline


def _execution(result: object, stdout: str = "", stderr: str = "") -> dict:
    return {"result": result, "stdout": stdout, "stderr": stderr}


def _run_snippet(
    target: Path, *, registered: bool, loadable: bool, export_status: int = 0
) -> dict:
    """Execute the worker snippet the way IDA Nexus does, against stub modules."""
    calls: list[str] = []
    state = {"registered": registered}

    def eval_idc(expression: str):
        calls.append(expression)
        assert expression.startswith("BinExportBinary(")
        path = json.loads(expression[len("BinExportBinary(") : -1])
        if not state["registered"]:
            return "IDC_FAILURE: undefined function BinExportBinary"
        if export_status == 0:
            Path(path).write_bytes(b"BinExport")
        return export_status

    def load_plugin(name: str):
        if not loadable:
            return None
        state["registered"] = True
        return object()

    idc = types.ModuleType("idc")
    idc.eval_idc = eval_idc
    ida_loader = types.ModuleType("ida_loader")
    ida_loader.load_plugin = load_plugin
    ida_auto = types.ModuleType("ida_auto")
    ida_auto.auto_wait = lambda: calls.append("auto_wait")
    stubs = {"idc": idc, "ida_loader": ida_loader, "ida_auto": ida_auto}

    code = _EXPORT_TEMPLATE.substitute(
        output=json.dumps(str(target)),
        plugins=json.dumps(list(PLUGIN_NAMES)),
    )
    module = ast.parse(code)
    namespace: dict = {}
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        # Nexus runs the leading statements and returns the trailing expression.
        exec(  # noqa: S102 -- mirrors the Nexus worker execution
            compile(ast.Module(module.body[:-1], []), "<snippet>", "exec"),
            namespace,
            namespace,
        )
        outcome = eval(  # mirrors the Nexus worker execution
            compile(ast.Expression(module.body[-1].value), "<snippet>", "eval"),
            namespace,
            namespace,
        )
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    outcome["calls"] = calls
    return outcome


def test_snippet_exports_through_the_registered_idc_extension(tmp_path: Path) -> None:
    # A path with a space and a quote proves the IDC string literal escaping.
    target = tmp_path / 'odd "dir' / "sample.bin.BinExport"
    target.parent.mkdir()

    outcome = _run_snippet(target, registered=True, loadable=False)

    assert outcome["idc_result"] == 0
    assert outcome["exists"] and outcome["size"] == len(b"BinExport")
    assert outcome["plugins_loaded"] == []
    assert outcome["calls"][0] == "auto_wait"
    assert target.read_bytes() == b"BinExport"


def test_snippet_loads_the_plugin_once_when_the_extension_is_missing(
    tmp_path: Path,
) -> None:
    target = tmp_path / "sample.bin.BinExport"

    outcome = _run_snippet(target, registered=False, loadable=True)

    assert outcome["idc_result"] == 0
    assert outcome["plugins_loaded"] == [PLUGIN_NAMES[0]]
    assert outcome["exists"]


def test_snippet_reports_a_missing_plugin(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin.BinExport"

    outcome = _run_snippet(target, registered=False, loadable=False)

    assert str(outcome["idc_result"]).startswith("IDC_FAILURE")
    assert outcome["plugins_loaded"] == []
    assert not outcome["exists"]


def test_check_export_hints_at_the_missing_plugin(tmp_path: Path) -> None:
    with pytest.raises(ExportError, match="install binexport12_ida.so"):
        _check_export(
            tmp_path / "sample.bin",
            tmp_path / "sample.bin.BinExport",
            _execution({"idc_result": "IDC_FAILURE: undefined", "plugins_loaded": []}),
        )


def test_check_export_reports_a_missing_output_file(tmp_path: Path) -> None:
    with pytest.raises(ExportError, match="wrote no file"):
        _check_export(
            tmp_path / "sample.bin",
            tmp_path / "sample.bin.BinExport",
            _execution(
                {"idc_result": 0, "exists": False, "size": 0}, stderr="ida said no"
            ),
        )


def test_check_export_reports_a_failing_export(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin.BinExport"
    target.write_bytes(b"x")

    with pytest.raises(ExportError, match="reported error 666"):
        _check_export(
            tmp_path / "sample.bin",
            target,
            _execution({"idc_result": 666, "exists": True, "size": 1}),
        )


@pytest.mark.parametrize("status", [0, None])
def test_check_export_accepts_eok_and_an_unset_idc_value(
    tmp_path: Path, status: int | None
) -> None:
    target = tmp_path / "sample.bin.BinExport"
    target.write_bytes(b"x")

    _check_export(
        tmp_path / "sample.bin",
        target,
        _execution({"idc_result": status, "exists": True, "size": 1}),
    )


def test_export_is_reused_when_newer_than_the_binary(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    export = output_dir / "sample.bin.BinExport"
    export.write_bytes(b"cached")
    os.utime(export, (binary.stat().st_atime + 10, binary.stat().st_mtime + 10))
    monkeypatch.setattr(
        "bindiff_mcp.export._run_export",
        lambda *_: pytest.fail("IDA must not run for a current export"),
    )

    result = export_binary(binary, output_dir)

    assert result.reused is True
    assert result.binexport == export
    assert export.read_bytes() == b"cached"


def test_stale_export_is_replaced(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    export = output_dir / "sample.bin.BinExport"
    export.write_bytes(b"stale")
    os.utime(export, (binary.stat().st_atime - 10, binary.stat().st_mtime - 10))
    exported: list[tuple[Path, Path]] = []

    def fake_run_export(source: Path, target: Path, **_: object) -> None:
        # The stale file must be gone before IDA writes the new one.
        assert not target.exists()
        exported.append((source, target))
        target.write_bytes(b"fresh")

    monkeypatch.setattr("bindiff_mcp.export._run_export", fake_run_export)

    result = export_binary(binary, output_dir)

    assert result.reused is False
    assert exported == [(binary.resolve(), export)]
    assert export.read_bytes() == b"fresh"


def test_missing_binary_is_rejected_before_ida_runs(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "bindiff_mcp.export._run_export",
        lambda *_: pytest.fail("IDA must not run for a missing binary"),
    )

    with pytest.raises(ExportError, match="binary not found"):
        export_binary(tmp_path / "nope.bin", tmp_path)


def test_concurrent_exports_of_one_binary_run_ida_once(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    output_dir = tmp_path / "out"
    exporting = threading.Event()
    finish = threading.Event()
    exports: list[Path] = []

    def slow_run_export(source: Path, target: Path, **_: object) -> None:
        exports.append(target)
        exporting.set()
        assert finish.wait(5)
        target.write_bytes(b"fresh")

    monkeypatch.setattr("bindiff_mcp.export._run_export", slow_run_export)
    results: list[ExportResult] = []
    waiting = threading.Event()

    def second_progress(state: str) -> None:
        if state.startswith("waiting"):
            waiting.set()

    first = threading.Thread(
        target=lambda: results.append(export_binary(binary, output_dir))
    )
    second = threading.Thread(
        target=lambda: results.append(
            export_binary(binary, output_dir, progress=second_progress)
        )
    )
    first.start()
    assert exporting.wait(5)
    second.start()
    # IDA Nexus would hand both callers one database; the second must wait.
    assert waiting.wait(5)
    finish.set()
    first.join(5)
    second.join(5)

    assert len(exports) == 1
    assert sorted(result.reused for result in results) == [False, True]


class _EndlessAnalysis:
    """Stands in for the Nexus manager of a binary IDA never finishes analyzing."""

    def __init__(self) -> None:
        self.closed: list[str] = []
        self.executed = False

    def open_database(self, path: str, *, set_current: bool) -> dict:
        return {"instance_id": "worker"}

    def wait_autoanalysis(self, instance_id: str, timeout: float) -> dict:
        time.sleep(timeout)
        raise RemoteError("operation_timeout", "analysis timed out", 408)

    def execute_python(self, *_: object, **__: object) -> dict:
        self.executed = True
        return {}

    def close_database(self, instance_id: str) -> None:
        self.closed.append(instance_id)


def test_autoanalysis_stops_at_the_job_limit_and_releases_ida(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    nexus = _EndlessAnalysis()
    monkeypatch.setattr("bindiff_mcp.export.DATABASE_MANAGER", nexus)

    with pytest.raises(TimeLimitError, match="autoanalysis of sample.bin"):
        export_binary(binary, tmp_path / "out", deadline=Deadline.after(0.2))

    assert nexus.closed == ["worker"]
    assert not nexus.executed
    assert list((tmp_path / "out").iterdir()) == []


_SLEEPS = "import time\nprint(flush=True)\ntime.sleep(60)\n"
_SPAWNS_GRANDCHILD = (
    "import subprocess, sys\n"
    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
    "print(child.pid, flush=True)\n"
    "child.wait()\n"
)


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads /proc")
def test_a_worker_left_running_is_killed_and_its_leftovers_dropped(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("bindiff_mcp.export._WORKER_EXIT_SECONDS", 0.5)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    (tmp_path / "sample.bin.i64").write_bytes(b"the database last packed")
    # What a killed worker leaves: an unlocked .id0 whose B-tree is still open.
    (tmp_path / "sample.bin.id0").write_bytes(
        bytes(18) + b"\x01" + b"B-tree v2" + bytes(64)
    )
    (tmp_path / "sample.bin.nam").write_bytes(b"names")
    stuck = subprocess.Popen([sys.executable, "-c", _SLEEPS], stdout=subprocess.PIPE)
    try:
        assert stuck.stdout is not None
        stuck.stdout.readline()

        _stop_worker(stuck.pid, binary)

        assert stuck.wait(5) == -signal.SIGKILL
    finally:
        stuck.kill()
        stuck.wait(5)
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "sample.bin",
        "sample.bin.i64",
    ]


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads /proc")
def test_a_process_this_server_did_not_spawn_is_never_stopped(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("bindiff_mcp.export._WORKER_EXIT_SECONDS", 0.5)
    parent = subprocess.Popen(
        [sys.executable, "-c", _SPAWNS_GRANDCHILD], stdout=subprocess.PIPE
    )
    assert parent.stdout is not None
    foreign = int(parent.stdout.readline())
    try:
        _stop_worker(foreign, tmp_path / "sample.bin")

        os.kill(foreign, 0)  # still running
    finally:
        with suppress(ProcessLookupError):
            os.kill(foreign, signal.SIGKILL)
        parent.kill()
        parent.wait(5)
