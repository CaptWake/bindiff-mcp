"""HTTP transport lifecycle: serve, answer, and exit on SIGTERM."""

from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

STARTUP_TIMEOUT = 30.0
SHUTDOWN_TIMEOUT = 10.0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _initialize(url: str) -> dict:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "tests", "version": "0"},
            },
        }
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def test_http_server_serves_and_stops_on_sigterm() -> None:
    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "bindiff_mcp.cli",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        payload: dict | None = None
        while time.monotonic() < deadline:
            if server.poll() is not None:
                pytest.fail(f"server exited early with {server.returncode}")
            try:
                payload = _initialize(url)
                break
            except (urllib.error.URLError, OSError):
                time.sleep(0.2)
        assert payload is not None, "server did not answer initialize"
        assert payload["result"]["serverInfo"]["name"] == "bindiff"

        # SIGTERM is what `docker stop` sends; stopping must not need SIGKILL.
        server.send_signal(signal.SIGTERM)
        assert server.wait(timeout=SHUTDOWN_TIMEOUT) == 0
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=SHUTDOWN_TIMEOUT)
