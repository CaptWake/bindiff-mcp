"""Where a comparison writes its results."""

from __future__ import annotations

from pathlib import Path

from bindiff_mcp.compare import _pair_folder

_PAIR = (Path("/in/C# app?.exe"), Path("/in/app (patched).exe"))
_BYTES = ("a" * 64, "b" * 64)


def test_a_pair_folder_is_named_after_both_binaries_in_safe_characters() -> None:
    assert _pair_folder(*_PAIR, _BYTES).startswith("C_app_.exe_vs_app_patched_.exe-")


def test_other_builds_with_the_same_names_get_another_folder() -> None:
    folder = _pair_folder(*_PAIR, _BYTES)

    assert _pair_folder(*_PAIR, _BYTES) == folder
    assert _pair_folder(*_PAIR, ("a" * 64, "c" * 64)) != folder
