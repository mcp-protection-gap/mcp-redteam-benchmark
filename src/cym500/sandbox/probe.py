"""Sandbox-side probe: install command launches the server, we send tools/list.

Runs inside the Docker container. Reads INSTALL_COMMAND from env, spawns it,
performs an MCP initialize handshake over stdio, calls tools/list, dumps the
JSON-RPC envelopes to /work/tools_list.json, and exits.

Why hand-rolled rather than the SDK: the official MCP SDK auto-installs
optional features and pulls in extra deps; here we want a minimal, auditable
client that only does what we need.
"""
from __future__ import annotations

import json
import os
import select
import shlex
import subprocess
import sys
import time
import uuid
from typing import Any

# Bytes read from the child's stdout but not yet consumed as a full line. Held
# at module scope so it survives across the two _recv calls (initialize, then
# tools/list): a server may emit both responses in one write.
_stdout_buf = b""

PROTOCOL_VERSION = os.environ.get("MCP_PROTOCOL_VERSION", "2025-06-18")
INSTALL_COMMAND = os.environ["INSTALL_COMMAND"]
INSTALL_TIMEOUT = int(os.environ.get("INSTALL_TIMEOUT", "60"))
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "30"))


def _next_id() -> str:
    return str(uuid.uuid4())


def _send(proc: subprocess.Popen, payload: dict[str, Any]) -> None:
    line = json.dumps(payload) + "\n"
    proc.stdin.write(line.encode())  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]


def _recv(proc: subprocess.Popen, deadline: float) -> dict[str, Any]:
    """Read JSON-RPC lines from the child until one parses, or the deadline passes.

    Must never block past ``deadline``. ``proc.stdout.readline()`` cannot give
    that guarantee: it blocks indefinitely when the child keeps stdout open but
    writes nothing (e.g. an install that hangs), so the deadline is only checked
    between reads and never reached. We select() on the raw fd with the time
    remaining as the wait bound, then drain whatever is available with os.read
    and split complete lines out of a persistent buffer.
    """
    global _stdout_buf
    fd = proc.stdout.fileno()  # type: ignore[union-attr]
    while True:
        # Consume any complete line already buffered before waiting on more.
        if b"\n" in _stdout_buf:
            raw, _stdout_buf = _stdout_buf.split(b"\n", 1)
            try:
                return json.loads(raw.decode())
            except json.JSONDecodeError:
                continue
        remaining = deadline - time.time()
        if remaining <= 0:
            raise TimeoutError("probe: no response within deadline")
        ready, _, _ = select.select([fd], [], [], min(remaining, 1.0))
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:  # EOF: child closed stdout, no full line left to parse
            raise TimeoutError("probe: stdout closed before a response")
        _stdout_buf += chunk


def _await_response(recv, want_id: str) -> dict[str, Any]:
    """Return the JSON-RPC response whose id is ``want_id``.

    A server may interleave notifications (e.g. ``notifications/tools/
    list_changed``) or its own requests before answering. Taking the first
    message as the answer misreads such a server as exposing no tools, so
    messages without the matching id are skipped. ``recv`` enforces the deadline.
    """
    while True:
        msg = recv()
        if isinstance(msg, dict) and msg.get("id") == want_id and (
            "result" in msg or "error" in msg
        ):
            return msg


def main() -> int:
    parts = shlex.split(INSTALL_COMMAND)
    proc = subprocess.Popen(
        parts,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    try:
        # 1. initialize
        init_id = _next_id()
        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "cym500-probe", "version": "0.1.0"},
                },
            },
        )
        init_deadline = time.time() + PROBE_TIMEOUT
        init = _await_response(lambda: _recv(proc, init_deadline), init_id)

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # 2. tools/list
        list_id = _next_id()
        _send(proc, {"jsonrpc": "2.0", "id": list_id, "method": "tools/list"})
        list_deadline = time.time() + PROBE_TIMEOUT
        tools = _await_response(lambda: _recv(proc, list_deadline), list_id)

        out = {
            "initialize_response": init,
            "tools_list_response": tools,
            "protocol_version": PROTOCOL_VERSION,
        }
        with open("/work/tools_list.json", "w") as f:
            json.dump(out, f, indent=2)
        return 0
    except Exception as e:  # noqa: BLE001
        # Capture the server's stderr so failures can be classified downstream
        # (missing config/env, package crash, not-an-MCP-server, slow start).
        with open("/work/tools_list.json", "w") as f:
            json.dump(
                {"error": str(e), "type": type(e).__name__, "stderr": _drain_stderr(proc)},
                f,
            )
        return 1
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _drain_stderr(proc: subprocess.Popen, limit: int = 4000) -> str:
    try:
        proc.terminate()
        _, err = proc.communicate(timeout=5)
    except Exception:
        try:
            proc.kill()
            _, err = proc.communicate(timeout=5)
        except Exception:
            err = b""
    return (err or b"").decode(errors="replace")[-limit:]


if __name__ == "__main__":
    sys.exit(main())
