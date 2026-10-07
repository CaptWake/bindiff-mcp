"""MCP server exposing BinExport and BinDiff to reverse-engineering agents.

Two tools are served:

- ``binexport(binary)``: export one binary to the BinExport v2 format
- ``bindiff_compare(primary_binary, secondary_binary)``: export both binaries
  and diff them, writing the matched/unmatched function lists as JSON

Exports run through IDA Nexus, so a binary already open in the IDA GUI is
exported from that database; otherwise a headless idalib worker is spawned.
IDA Pro, the BinExport IDA plugin and the BinDiff differ must be installed.
"""

from __future__ import annotations

import atexit
import ipaddress
import json
import signal
import threading
from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any

from zeromcp import McpServer, McpToolError

from bindiff_mcp.compare import run_compare, run_export
from bindiff_mcp.errors import BindiffMcpError
from bindiff_mcp.export import DATABASE_MANAGER

try:
    PACKAGE_VERSION = version("bindiff-mcp")
except PackageNotFoundError:  # running from a source checkout
    PACKAGE_VERSION = "0+unknown"

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8745

MCP_SERVER_INSTRUCTIONS = (
    "Binary diffing with IDA Pro, BinExport and BinDiff: export executables to "
    "BinExport v2 and compare two builds (original vs patched, vulnerable vs "
    "fixed) to get identical, changed and unmatched functions with addresses, "
    "names and similarity scores. Use instead of byte-level diff tools when the "
    "binaries were recompiled or relocated."
)

mcp = McpServer(
    "bindiff", version=PACKAGE_VERSION, instructions=MCP_SERVER_INSTRUCTIONS
)


def _as_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2)


@mcp.tool(title="Export a binary with BinExport")
async def binexport(
    binary: Annotated[str, "Path to the binary to export."],
    output_results_dir: Annotated[
        str, "Directory to save the result files (default: current dir)."
    ] = ".",
) -> str:
    """
    Export the binary using the binexport tool from IDA

    The binary is analyzed by IDA Pro and written as
    ``<output_results_dir>/<binary name>.BinExport``. An export that is newer
    than the binary is reused instead of re-analyzing it. Returns JSON with the
    export path, architecture, SHA-256 and function count.

    Args:
        binary: Path to the binary
        output_results_dir: Directory to save the result files (default: current dir)
    """

    try:
        return _as_json(await run_export(binary, output_results_dir))
    except BindiffMcpError as error:
        raise McpToolError(str(error)) from error


@mcp.tool(title="Diff two binaries with BinDiff")
async def bindiff_compare(
    primary_binary: Annotated[str, "Path to the first binary (e.g. original)."],
    secondary_binary: Annotated[str, "Path to the second binary (e.g. patched)."],
    output_results_dir: Annotated[
        str, "Directory to save the result files (default: current dir)."
    ] = ".",
) -> str:
    """
    Compares two binary files using IDA Pro and BinDiff.
    Resulting detailed difference lists are saved to the specified directory (default: current directory).
    Generated files:
    1. matched_similar.json (Identical functions)
    2. matched_different.json (Matched but Changed functions)
    3. primary_only.json (Unmatched in Primary)
    4. secondary_only.json (Unmatched in Secondary)

    Both binaries are exported in parallel, diffed with BinDiff, and the match
    lists are written as JSON. matched_different.json is ordered by similarity,
    most divergent first. Returns JSON with the overall similarity and
    confidence, per-list counts and the path of every file written.

    Args:
        primary_binary: Path to the first binary (e.g. original)
        secondary_binary: Path to the second binary (e.g. patched)
        output_results_dir: Directory to save the result files (default: current dir)
    """

    try:
        return _as_json(
            await run_compare(primary_binary, secondary_binary, output_results_dir)
        )
    except BindiffMcpError as error:
        raise McpToolError(str(error)) from error


_SHUTDOWN_LOCK = threading.Lock()
_SHUTDOWN_DONE = False


def shutdown() -> None:
    """Release every IDA database lease held by this process."""
    global _SHUTDOWN_DONE
    with _SHUTDOWN_LOCK:
        if _SHUTDOWN_DONE:
            return
        _SHUTDOWN_DONE = True
    with suppress(Exception):
        DATABASE_MANAGER.shutdown()


atexit.register(shutdown)


def _install_stdio_signal_handlers() -> None:
    def stop(signum: int, _frame: Any) -> None:
        shutdown()
        signal.signal(signum, signal.SIG_DFL)
        signal.raise_signal(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, stop)


def serve_stdio() -> None:
    """Serve MCP over stdio until the peer closes its input."""
    _install_stdio_signal_handlers()
    try:
        mcp.stdio()
    finally:
        shutdown()


def serve_http(host: str = DEFAULT_HTTP_HOST, port: int = DEFAULT_HTTP_PORT) -> None:
    """Serve Streamable HTTP until the process is signalled."""
    _validate_http_address(host, port)
    stop_requested = threading.Event()

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_requested.set()

    previous = {
        signum: signal.signal(signum, request_stop)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        # Serve in a background thread: mcp.stop() calls HTTPServer.shutdown(),
        # which deadlocks when invoked from the thread running serve_forever.
        mcp.serve(host, port, background=True)
        while not stop_requested.wait(1.0):
            pass
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        with suppress(Exception):
            mcp.stop()
        shutdown()


def _validate_http_address(host: str, port: int) -> None:
    if not host.strip():
        raise ValueError("host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not _is_loopback_host(host):
        # The tools read and write local files on behalf of any caller, so a
        # non-loopback bind must be a deliberate choice (e.g. a container).
        print(f"[bindiff-mcp] warning: serving on non-loopback address {host}")


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


__all__ = [
    "DEFAULT_HTTP_HOST",
    "DEFAULT_HTTP_PORT",
    "bindiff_compare",
    "binexport",
    "mcp",
    "serve_http",
    "serve_stdio",
    "shutdown",
]
