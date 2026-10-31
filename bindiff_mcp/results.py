"""Turn a BinDiff database and its two exports into the JSON result files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bindiff_mcp.files import write_text_atomic
from bindiff_mcp.reader import Diff, Function, FunctionMatch, Program

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


def program_metadata(program: Program) -> dict[str, Any]:
    """Summarize an exported program for a tool response."""
    return {
        "name": program.name,
        "architecture": program.architecture,
        "sha256": program.sha256,
        "functions": len(program.functions),
    }


def match_entry(
    match: FunctionMatch, primary: Function, secondary: Function
) -> dict[str, Any]:
    """Describe one matched function pair."""
    return {
        "primary_address": hex(match.address1),
        "primary_name": match.name1 or primary.name,
        "secondary_address": hex(match.address2),
        "secondary_name": match.name2 or secondary.name,
        "similarity": round(match.similarity, 4),
        "confidence": round(match.confidence, 4),
        "algorithm": match.algorithm,
    }


def function_entry(function: Function) -> dict[str, Any]:
    """Describe one unmatched function."""
    return {
        "address": hex(function.address),
        "name": function.name,
        "type": function.type,
    }


def collect_results(
    diff: Diff, primary: Program, secondary: Program
) -> dict[str, list[dict[str, Any]]]:
    """Build every result list from a BinDiff database and its two exports."""
    # One match per address and side; a later row replaces an earlier one.
    by_primary = {match.address1: match for match in diff.matches}
    by_secondary = {match.address2: match for match in diff.matches}

    identical: list[dict[str, Any]] = []
    changed: list[tuple[float, int, dict[str, Any]]] = []
    for match in by_primary.values():
        first = primary.functions.get(match.address1)
        second = secondary.functions.get(match.address2)
        if first is None or second is None:
            continue  # a match for a function the export does not list
        entry = match_entry(match, first, second)
        if match.similarity >= IDENTICAL_SIMILARITY:
            identical.append(entry)
        else:
            changed.append((match.similarity, match.address1, entry))
    identical.sort(key=lambda entry: int(entry["primary_address"], 16))
    # Most divergent matches first: that is where a patch analysis starts.
    changed.sort(key=lambda item: (item[0], item[1]))
    return {
        "matched_similar": identical,
        "matched_different": [entry for _, _, entry in changed],
        "primary_only": _unmatched(primary, by_primary),
        "secondary_only": _unmatched(secondary, by_secondary),
    }


def _unmatched(
    program: Program, matched: dict[int, FunctionMatch]
) -> list[dict[str, Any]]:
    return [
        function_entry(function)
        for address, function in sorted(program.functions.items())
        if address not in matched
    ]


def write_results(
    results: dict[str, list[dict[str, Any]]], output_dir: Path
) -> dict[str, dict[str, Any]]:
    """Write the four result files and report their sizes and paths."""
    counts: dict[str, Any] = {}
    files: dict[str, Any] = {}
    for key, filename in RESULT_FILES.items():
        path = output_dir / filename
        write_text_atomic(path, json.dumps(results[key], indent=2) + "\n")
        counts[key] = len(results[key])
        files[key] = str(path)
    return {"counts": counts, "files": files}
