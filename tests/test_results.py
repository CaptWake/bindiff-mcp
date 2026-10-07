"""Classification of BinDiff matches into the four agent-facing result files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bindiff import BinDiff

from bindiff_mcp.results import (
    RESULT_FILES,
    collect_results,
    program_metadata,
    write_results,
)
from tests.fixtures import IMPORTED, NORMAL, write_bindiff_database, write_binexport


@pytest.fixture
def diff(tmp_path: Path) -> BinDiff:
    primary = write_binexport(
        tmp_path / "primary.bin.BinExport",
        "primary.bin",
        [
            (0x401000, "untouched", NORMAL),
            (0x401100, "patched_check", NORMAL),
            (0x401200, "refactored", NORMAL),
            (0x401300, "removed_helper", NORMAL),
            (0x402000, "memcpy", IMPORTED),
        ],
    )
    secondary = write_binexport(
        tmp_path / "secondary.bin.BinExport",
        "secondary.bin",
        [
            (0x501000, "untouched", NORMAL),
            (0x501100, "patched_check", NORMAL),
            (0x501200, "refactored", NORMAL),
            (0x501300, "added_helper", NORMAL),
            (0x502000, "memcpy", IMPORTED),
        ],
    )
    database = write_bindiff_database(
        tmp_path / "primary_vs_secondary.BinDiff",
        [
            (0x401200, "refactored", 0x501200, "refactored", 0.91, 0.95),
            (0x401000, "untouched", 0x501000, "untouched", 1.0, 0.99),
            (0x401100, "patched_check", 0x501100, "patched_check", 0.42, 0.80),
            (0x402000, "memcpy", 0x502000, "memcpy", 1.0, 0.99),
        ],
    )
    return BinDiff(str(primary), str(secondary), database)


def test_identical_matches_are_separated_at_similarity_one(diff: BinDiff) -> None:
    results = collect_results(diff)

    assert [entry["primary_address"] for entry in results["matched_similar"]] == [
        "0x401000",
        "0x402000",
    ]
    assert all(entry["similarity"] == 1.0 for entry in results["matched_similar"])
    assert all(entry["similarity"] < 1.0 for entry in results["matched_different"])


def test_changed_matches_are_ordered_most_divergent_first(diff: BinDiff) -> None:
    changed = collect_results(diff)["matched_different"]

    assert [entry["similarity"] for entry in changed] == [0.42, 0.91]
    assert changed[0] == {
        "primary_address": "0x401100",
        "primary_name": "patched_check",
        "secondary_address": "0x501100",
        "secondary_name": "patched_check",
        "similarity": 0.42,
        "confidence": 0.8,
        "algorithm": "manual",
    }


def test_unmatched_functions_are_reported_per_side(diff: BinDiff) -> None:
    results = collect_results(diff)

    assert results["primary_only"] == [
        {"address": "0x401300", "name": "removed_helper", "type": "normal"}
    ]
    assert results["secondary_only"] == [
        {"address": "0x501300", "name": "added_helper", "type": "normal"}
    ]


def test_write_results_writes_every_file_with_matching_counts(
    diff: BinDiff, tmp_path: Path
) -> None:
    output_dir = tmp_path / "results"
    output_dir.mkdir()

    summary = write_results(diff, output_dir)

    assert summary["counts"] == {
        "matched_similar": 2,
        "matched_different": 2,
        "primary_only": 1,
        "secondary_only": 1,
    }
    for key, filename in RESULT_FILES.items():
        path = Path(summary["files"][key])
        assert path == output_dir / filename
        assert (
            len(json.loads(path.read_text(encoding="utf-8"))) == summary["counts"][key]
        )


def test_program_metadata_reports_export_identity(diff: BinDiff) -> None:
    assert program_metadata(diff.primary) == {
        "name": "primary.bin",
        "architecture": "x86-64",
        "sha256": "sha256-of-primary.bin",
        "functions": 5,
    }
