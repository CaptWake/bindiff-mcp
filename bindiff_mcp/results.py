"""Turn a parsed BinDiff database into the JSON result files agents consume."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bindiff import BinDiff
from bindiff.file import FunctionMatch
from bindiff.types import function_algorithm_str
from binexport import FunctionBinExport, ProgramBinExport

#: BinDiff scores structurally identical functions at 1.0; anything below
#: changed instructions, basic blocks or edges.
IDENTICAL_SIMILARITY = 1.0

#: Result file names, in the order they are documented to the agent.
RESULT_FILES: dict[str, str] = {
    "matched_similar": "matched_similar.json",
    "matched_different": "matched_different.json",
    "primary_only": "primary_only.json",
    "secondary_only": "secondary_only.json",
}


def program_metadata(program: ProgramBinExport) -> dict[str, Any]:
    """Summarize an exported program for a tool response."""
    meta = program.proto.meta_information
    return {
        "name": program.name,
        "architecture": program.architecture,
        "sha256": meta.executable_id,
        "functions": len(program),
    }


def match_entry(
    primary: FunctionBinExport,
    secondary: FunctionBinExport,
    match: FunctionMatch,
) -> dict[str, Any]:
    """Describe one matched function pair."""
    return {
        "primary_address": hex(match.address1),
        "primary_name": match.name1 or primary.name,
        "secondary_address": hex(match.address2),
        "secondary_name": match.name2 or secondary.name,
        "similarity": round(match.similarity, 4),
        "confidence": round(match.confidence, 4),
        "algorithm": function_algorithm_str(match.algorithm),
    }


def function_entry(function: FunctionBinExport) -> dict[str, Any]:
    """Describe one unmatched function."""
    return {
        "address": hex(function.addr),
        "name": function.name,
        "type": function.type.name.lower() if function.type else "unknown",
    }


def split_matches(diff: BinDiff) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split function matches into identical and changed pairs."""
    identical: list[dict[str, Any]] = []
    changed: list[tuple[float, int, dict[str, Any]]] = []
    for primary, secondary, match in diff.iter_function_matches():
        entry = match_entry(primary, secondary, match)
        if match.similarity >= IDENTICAL_SIMILARITY:
            identical.append(entry)
        else:
            changed.append((match.similarity, match.address1, entry))
    identical.sort(key=lambda entry: int(entry["primary_address"], 16))
    # Most divergent matches first: that is where a patch analysis starts.
    changed.sort(key=lambda item: (item[0], item[1]))
    return identical, [entry for _, _, entry in changed]


def unmatched_entries(functions: list[FunctionBinExport]) -> list[dict[str, Any]]:
    """Describe unmatched functions, ordered by address."""
    return [
        function_entry(function) for function in sorted(functions, key=lambda f: f.addr)
    ]


def collect_results(diff: BinDiff) -> dict[str, list[dict[str, Any]]]:
    """Build every result list from a loaded BinDiff database."""
    identical, changed = split_matches(diff)
    return {
        "matched_similar": identical,
        "matched_different": changed,
        "primary_only": unmatched_entries(diff.primary_unmatched_function()),
        "secondary_only": unmatched_entries(diff.secondary_unmatched_function()),
    }


def write_results(diff: BinDiff, output_dir: Path) -> dict[str, dict[str, Any]]:
    """Write the four result files and report their sizes and paths."""
    results = collect_results(diff)
    counts: dict[str, Any] = {}
    files: dict[str, Any] = {}
    for key, filename in RESULT_FILES.items():
        path = output_dir / filename
        path.write_text(json.dumps(results[key], indent=2) + "\n", encoding="utf-8")
        counts[key] = len(results[key])
        files[key] = str(path)
    return {"counts": counts, "files": files}
