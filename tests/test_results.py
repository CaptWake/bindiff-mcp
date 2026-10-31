"""Classification of BinDiff matches into the four agent-facing result files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

import pytest
from binexport.binexport2_pb2 import BinExport2  # ty: ignore[unresolved-import]

from bindiff_mcp.reader import (
    Diff,
    Program,
    exported_binary_sha256,
    read_diff,
    read_program,
)
from bindiff_mcp.results import (
    RESULT_FILES,
    collect_results,
    program_metadata,
    write_results,
)
from tests.fixtures import IMPORTED, NORMAL, write_bindiff_database, write_binexport


class Loaded(NamedTuple):
    diff: Diff
    primary: Program
    secondary: Program


def _write_pair(directory: Path) -> tuple[Path, Path, Path]:
    primary = write_binexport(
        directory / "primary.bin.BinExport",
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
        directory / "secondary.bin.BinExport",
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
        directory / "primary_vs_secondary.BinDiff",
        [
            (0x401200, "refactored", 0x501200, "refactored", 0.91, 0.95),
            (0x401000, "untouched", 0x501000, "untouched", 1.0, 0.99),
            (0x401100, "patched_check", 0x501100, "patched_check", 0.42, 0.80),
            (0x402000, "memcpy", 0x502000, "memcpy", 1.0, 0.99),
        ],
    )
    return primary, secondary, database


@pytest.fixture
def loaded(tmp_path: Path) -> Loaded:
    primary, secondary, database = _write_pair(tmp_path)
    return Loaded(read_diff(database), read_program(primary), read_program(secondary))


def test_identical_matches_are_separated_at_similarity_one(loaded: Loaded) -> None:
    results = collect_results(*loaded)

    assert [entry["primary_address"] for entry in results["matched_similar"]] == [
        "0x401000",
        "0x402000",
    ]
    assert all(entry["similarity"] == 1.0 for entry in results["matched_similar"])
    assert all(entry["similarity"] < 1.0 for entry in results["matched_different"])


def test_changed_matches_are_ordered_most_divergent_first(loaded: Loaded) -> None:
    changed = collect_results(*loaded)["matched_different"]

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


def test_unmatched_functions_are_reported_per_side(loaded: Loaded) -> None:
    results = collect_results(*loaded)

    assert results["primary_only"] == [
        {"address": "0x401300", "name": "removed_helper", "type": "normal"}
    ]
    assert results["secondary_only"] == [
        {"address": "0x501300", "name": "added_helper", "type": "normal"}
    ]


def test_write_results_writes_every_file_with_matching_counts(
    loaded: Loaded, tmp_path: Path
) -> None:
    output_dir = tmp_path / "results"
    output_dir.mkdir()

    summary = write_results(collect_results(*loaded), output_dir)

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


def test_program_metadata_reports_export_identity(loaded: Loaded) -> None:
    assert program_metadata(loaded.primary) == {
        "name": "primary.bin",
        "architecture": "x86-64",
        "sha256": "sha256-of-primary.bin",
        "functions": 5,
    }


def test_files_with_url_characters_in_their_path_are_read(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    written = _write_pair(plain)
    # Renamed afterwards: python-bindiff cannot create a database at such a path.
    directory = plain.rename(tmp_path / "C# builds?v=2 100%41")
    primary, secondary, database = (directory / path.name for path in written)

    diff = read_diff(database)

    assert (diff.similarity, len(diff.matches)) == (0.75, 4)
    assert len(read_program(primary).functions) == 5
    assert len(read_program(secondary).functions) == 5
    assert [path.name for path in tmp_path.iterdir()] == [directory.name]


def test_the_source_hash_is_read_wherever_the_meta_information_is(
    tmp_path: Path,
) -> None:
    export = write_binexport(
        tmp_path / "first.BinExport",
        "sample.bin",
        [(0x401000, "main", NORMAL)],
        executable_id="AB" * 32,
    )
    # Protobuf merges concatenated messages, so this file is equally valid
    # with the meta information last instead of first.
    program = BinExport2.FromString(export.read_bytes())
    meta_last = BinExport2(meta_information=program.meta_information)
    program.ClearField("meta_information")
    reordered = tmp_path / "last.BinExport"
    reordered.write_bytes(program.SerializeToString() + meta_last.SerializeToString())

    assert exported_binary_sha256(export) == "ab" * 32
    assert exported_binary_sha256(reordered) == "ab" * 32
    assert exported_binary_sha256(tmp_path / "missing.BinExport") is None
