"""Command-line interface for the BinDiff MCP server."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bindiff-mcp",
        description="MCP server exposing BinExport and BinDiff binary diffing.",
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("stdio", help="serve MCP over stdio (default)")
    http = commands.add_parser("http", help="serve MCP over Streamable HTTP")
    http.add_argument("--host", default=None, help="bind address (default: 127.0.0.1)")
    http.add_argument(
        "--port", type=int, default=None, help="bind port (default: 8745)"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))

    # Imported lazily so --help does not pay for the IDA and protobuf imports.
    from bindiff_mcp.mcp import (
        DEFAULT_HTTP_HOST,
        DEFAULT_HTTP_PORT,
        serve_http,
        serve_stdio,
    )

    if arguments.command == "http":
        serve_http(
            arguments.host if arguments.host is not None else DEFAULT_HTTP_HOST,
            arguments.port if arguments.port is not None else DEFAULT_HTTP_PORT,
        )
        return 0

    serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
