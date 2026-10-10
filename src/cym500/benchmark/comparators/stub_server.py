"""Parametrisable stdio MCP server used to feed tool definitions to a scanner.

Snyk Agent Scan / mcp-scan analyses the tools a *live* MCP server advertises, so
to score an attack case (or a benign trace) we stand up a throwaway server that
exposes exactly the tool definition(s) under test and let the scanner connect to
it. The definitions are read from the JSON file named in MCPSTUB_TOOLS_FILE
(a list of MCP tool objects: name, description, inputSchema).

The server answers the minimum handshake a scanner performs: initialize,
tools/list, and empty prompts/list and resources/list (mcp-scan queries all
three and blocks until each replies). It performs no I/O beyond stdio.

For in-path gateway benchmarking the stub can also answer ``tools/call`` with a
configured output (MCPSTUB_OUTPUTS_FILE: a JSON object mapping tool name to the
text it returns), and can issue one server-initiated ``sampling/createMessage``
request during a call (MCPSTUB_SAMPLING_FILE: the request params). The call's
result then reports whether the sampling request was answered, which is how a
gateway that does not relay sampling is told apart from one that does.
"""
from __future__ import annotations

import json
import os
import sys

_TOOLS: list[dict] = []


def _load_tools() -> list[dict]:
    path = os.environ.get("MCPSTUB_TOOLS_FILE")
    if not path or not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def _load_json(var: str):
    path = os.environ.get(var)
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _read_until(req_id: str) -> dict | None:
    """Read stdin until the response to our own request arrives (or EOF)."""
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == req_id and ("result" in msg or "error" in msg):
            return msg
    return None


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(req_id, result) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def main() -> int:
    tools = _load_tools()
    outputs = _load_json("MCPSTUB_OUTPUTS_FILE") or {}
    sampling = _load_json("MCPSTUB_SAMPLING_FILE")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "initialize":
            _result(
                req_id,
                {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                    "serverInfo": {"name": "cym500-scan-stub", "version": "0.1.0"},
                },
            )
        elif method == "notifications/initialized":
            continue  # notification: no reply
        elif method == "tools/list":
            _result(req_id, {"tools": tools})
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            text = outputs.get(name, "ok")
            if sampling is not None:
                _send({"jsonrpc": "2.0", "id": "stub-sampling-1",
                       "method": "sampling/createMessage", "params": sampling})
                reply = _read_until("stub-sampling-1")
                answered = bool(reply and "result" in reply)
                text = json.dumps({"sampling_answered": answered})
            _result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
        elif method == "prompts/list":
            _result(req_id, {"prompts": []})
        elif method == "resources/list":
            _result(req_id, {"resources": []})
        elif method == "resources/templates/list":
            _result(req_id, {"resourceTemplates": []})
        elif method == "ping":
            _result(req_id, {})
        elif req_id is not None:
            # Unknown request: reply with method-not-found rather than hang.
            _send({"jsonrpc": "2.0", "id": req_id,
                   "error": {"code": -32601, "message": "method not found"}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
