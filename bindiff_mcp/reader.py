"""Function-level reads of BinExport and BinDiff files.

python-binexport and python-bindiff build an object for every function, basic
block, instruction and call edge, and python-bindiff also loads every basic
block and instruction match. The result lists need function rows only; reading
FontLab's diff through those libraries took 100 s and 7 GiB before either
export was even loaded.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from bindiff.types import FunctionAlgorithm, function_algorithm_str
from binexport.binexport2_pb2 import BinExport2  # ty: ignore[unresolved-import]
from binexport.types import FunctionType

#: SQLite holds the unsigned 64-bit addresses of a BinDiff database as signed.
_ADDRESS_MASK = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class Function:
    """A function of an exported program."""

    address: int
    name: str
    type: str


@dataclass(frozen=True, slots=True)
class Program:
    """What the result lists need from a BinExport file."""

    name: str
    architecture: str
    sha256: str
    functions: dict[int, Function]


@dataclass(frozen=True, slots=True)
class FunctionMatch:
    """One row of the ``function`` table of a BinDiff database."""

    address1: int
    name1: str
    address2: int
    name2: str
    similarity: float
    confidence: float
    algorithm: str


@dataclass(frozen=True, slots=True)
class Diff:
    """Overall scores and function matches of a BinDiff database."""

    similarity: float
    confidence: float
    matches: list[FunctionMatch]


def read_program(path: Path) -> Program:
    """Read the functions of a BinExport file, listed as python-binexport does."""
    proto = BinExport2()
    proto.ParseFromString(path.read_bytes())
    addresses = {
        _block_address(proto, flow_graph.entry_basic_block_index)
        for flow_graph in proto.flow_graph
    }
    names: dict[int, str] = {}
    types: dict[int, str] = {}
    for vertex in proto.call_graph.vertex:
        if vertex.address not in addresses:
            # Imports have no flow graph; other call graph entries without
            # one are not functions of the program.
            if vertex.type != BinExport2.CallGraph.Vertex.IMPORTED:
                continue
            addresses.add(vertex.address)
        types[vertex.address] = FunctionType.from_proto(vertex.type).name.lower()
        name = vertex.demangled_name or vertex.mangled_name
        if name:
            names[vertex.address] = name
    meta = proto.meta_information
    return Program(
        name=meta.executable_name,
        architecture=meta.architecture_name,
        sha256=meta.executable_id,
        functions={
            address: Function(
                address=address,
                name=names.get(address, f"sub_{address:X}"),
                type=types.get(address, "unknown"),
            )
            for address in addresses
        },
    )


def read_diff(path: Path) -> Diff:
    """Read the overall scores and the function matches of a BinDiff database."""
    # A file: URI percent-encodes the path, so '#', '?' and '%' in it stay
    # part of the file name instead of starting a fragment or a query.
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as database:
        similarity, confidence = database.execute(
            "SELECT similarity, confidence FROM metadata"
        ).fetchone()
        rows = database.execute(
            "SELECT address1, name1, address2, name2, similarity, confidence, "
            "algorithm FROM function"
        ).fetchall()
    return Diff(
        # Rounded like python-bindiff, which the result files were built with.
        similarity=float(f"{similarity:.3f}"),
        confidence=float(f"{confidence:.3f}"),
        matches=[
            FunctionMatch(
                address1=address1 & _ADDRESS_MASK,
                name1=name1,
                address2=address2 & _ADDRESS_MASK,
                name2=name2,
                similarity=match_similarity,
                confidence=match_confidence,
                algorithm=_algorithm_name(algorithm),
            )
            for (
                address1,
                name1,
                address2,
                name2,
                match_similarity,
                match_confidence,
                algorithm,
            ) in rows
        ],
    )


def _block_address(proto: BinExport2, block_index: int) -> int:
    """Address of a basic block, which is that of its first instruction."""
    first = proto.basic_block[block_index].instruction_index[0].begin_index
    return _instruction_address(proto, first)


def _instruction_address(proto: BinExport2, index: int) -> int:
    """Address of an instruction.

    BinExport records an address only for an instruction that does not directly
    follow the previous one; the others are found by adding up the sizes back to
    the last instruction that has one.
    """
    offset = 0
    while not proto.instruction[index].HasField("address") and index > 0:
        index -= 1
        offset += len(proto.instruction[index].raw_bytes)
    return proto.instruction[index].address + offset


def _algorithm_name(algorithm: int) -> str:
    try:
        return function_algorithm_str(FunctionAlgorithm(algorithm))
    except ValueError:
        return f"unknown ({algorithm})"
