"""Minimal, benign stdio MCP server used to exercise the sandbox harness.

Speaks just enough of the protocol for `probe.py`: an `initialize` handshake
and a `tools/list` reply advertising two trivial tools. No network, no writes,
no third-party dependencies, so it runs under the hardened sandbox
(network=none, read-only rootfs, dropped capabilities).
"""
import json
import sys


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        if method == "initialize":
            _send({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stub", "version": "0.0.1"},
                },
            })
        elif method == "tools/list":
            _send({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"tools": [
                    {"name": "echo", "description": "Echoes input",
                     "inputSchema": {"type": "object",
                                     "properties": {"text": {"type": "string"}}}},
                    {"name": "add", "description": "Adds a and b",
                     "inputSchema": {"type": "object",
                                     "properties": {"a": {"type": "number"},
                                                    "b": {"type": "number"}}}},
                ]},
            })
        # notifications/initialized and anything else are ignored.


if __name__ == "__main__":
    main()
