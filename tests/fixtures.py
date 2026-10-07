"""Synthetic BinExport and BinDiff fixtures, so tests need no IDA or differ."""

from __future__ import annotations

from pathlib import Path

from bindiff import BindiffFile
from binexport.binexport2_pb2 import BinExport2

NORMAL = BinExport2.CallGraph.Vertex.NORMAL
IMPORTED = BinExport2.CallGraph.Vertex.IMPORTED


def write_binexport(
    path: Path, name: str, functions: list[tuple[int, str, int]]
) -> Path:
    """Write a minimal BinExport file with one basic block per function."""
    program = BinExport2()
    program.meta_information.executable_name = name
    program.meta_information.executable_id = f"sha256-of-{name}"
    program.meta_information.architecture_name = "x86-64"
    for address, function_name, vertex_type in functions:
        vertex = program.call_graph.vertex.add()
        vertex.address = address
        vertex.type = vertex_type
        vertex.mangled_name = function_name
        if vertex_type == IMPORTED:
            continue
        instruction_index = len(program.instruction)
        instruction = program.instruction.add()
        instruction.address = address
        instruction.raw_bytes = b"\x90"
        block_index = len(program.basic_block)
        index_range = program.basic_block.add().instruction_index.add()
        index_range.begin_index = instruction_index
        index_range.end_index = instruction_index + 1
        flow_graph = program.flow_graph.add()
        flow_graph.basic_block_index.append(block_index)
        flow_graph.entry_basic_block_index = block_index
    path.write_bytes(program.SerializeToString())
    return path


def write_bindiff_database(
    path: Path,
    matches: list[tuple[int, str, int, str, float, float]],
    *,
    similarity: float = 0.75,
    confidence: float = 0.9,
) -> Path:
    """Write a BinDiff database holding the given function matches."""
    database = BindiffFile.create(
        str(path), "tests", "synthetic diff", similarity, confidence
    )
    database.add_file_matched("primary.bin.BinExport", "sha256-of-primary.bin")
    database.add_file_matched("secondary.bin.BinExport", "sha256-of-secondary.bin")
    for address1, name1, address2, name2, match_similarity, match_confidence in matches:
        database.add_function_match(
            address1, address2, name1, name2, match_similarity, match_confidence
        )
    database.commit()
    database.close()
    return path
