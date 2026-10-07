"""Export reuse rules, IDA worker snippet, and BinExport failure reporting."""

from __future__ import annotations

import ast
import json
import os
import sys
import types
from pathlib import Path

import pytest

from bindiff_mcp.errors import ExportError
from bindiff_mcp.export import (
    _EXPORT_TEMPLATE,
    PLUGIN_NAMES,
    _check_export,
    export_binary,
)


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

    def fake_run_export(source: Path, target: Path) -> None:
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
