"""In-path probe: drive a real MCP client through the Lasso gateway to a stub.

Stands up:  client -> mcp-gateway (plugins) -> stub server.
Lists tools (did the scanner block the server?) and, if a tool survives, calls
it (were request args / outputs masked or the call blocked?). Emits one JSON
line: whether the tool was exposed and the exact text the gateway forwarded.
The result dict is owned by main() and always printed, so the mcp stdio
teardown race ("cancel scope in a different task") cannot swallow it.
"""
import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp import types

STUB = Path(__file__).resolve().parent / "stub_server.py"


async def _sampling_handler(context, params):
    return types.CreateMessageResult(
        role="assistant",
        content=types.TextContent(type="text", text="SAMPLING_ANSWERED"),
        model="stub-model",
        stopReason="endTurn",
    )


async def run(out: dict, tool: dict, output_text, sampling, plugins, scan, py):
    tmp = Path(tempfile.mkdtemp(prefix="inpath-"))
    (tmp / "tools.json").write_text(json.dumps([tool]))
    stub_env = {"MCPSTUB_TOOLS_FILE": str(tmp / "tools.json")}
    if output_text is not None:
        (tmp / "outputs.json").write_text(json.dumps({tool["name"]: output_text}))
        stub_env["MCPSTUB_OUTPUTS_FILE"] = str(tmp / "outputs.json")
    if sampling is not None:
        (tmp / "sampling.json").write_text(json.dumps(sampling))
        stub_env["MCPSTUB_SAMPLING_FILE"] = str(tmp / "sampling.json")

    (tmp / "mcp.json").write_text(json.dumps({"mcpServers": {"lasso-gateway": {
        "servers": {"target": {"command": py, "args": [str(STUB)], "env": stub_env}}}}}))

    args = ["--mcp-json-path", str(tmp / "mcp.json")]
    for p in plugins:
        args += ["--plugin", p]
    if scan:
        args += ["--scan"]

    gw_bin = str(Path(sys.executable).with_name("mcp-gateway"))
    params = StdioServerParameters(command=gw_bin, args=args, env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, sampling_callback=_sampling_handler) as s:
            await s.initialize()
            names = [t.name for t in (await s.list_tools()).tools]
            out["tool_names"] = names
            out["listed"] = True
            target = next((n for n in names if n.endswith(tool["name"])), None)
            if target is None:
                return  # scanner blocked the server
            out["exposed"] = True
            call_args = {k: "x" for k in (tool.get("inputSchema", {}).get("properties") or {})}
            try:
                res = await s.call_tool(target, call_args)
                out["forwarded"] = json.dumps([c.model_dump() for c in res.content], default=str)
                out["is_error"] = bool(getattr(res, "isError", False))
            except Exception as e:
                out["blocked_call"] = True
                out["error"] = f"{type(e).__name__}: {e}"[:200]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--plugin", action="append", default=[])
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--py", default=sys.executable)
    ap.add_argument("--out", default=None, help="write result JSON here too")
    a = ap.parse_args()
    spec = json.loads(Path(a.spec).read_text())
    out = {"exposed": False, "forwarded": None, "error": None,
           "blocked_call": False, "listed": False}
    try:
        asyncio.run(run(out, spec["tool"], spec.get("output"), spec.get("sampling"),
                        a.plugin, a.scan, a.py))
    except BaseException as e:  # noqa: BLE001 - anyio teardown raises BaseExceptionGroup
        if not out["listed"]:
            out["error"] = f"{type(e).__name__}: {e}"[:300]
        else:
            out["teardown_note"] = type(e).__name__
    line = json.dumps(out)
    if a.out:
        Path(a.out).write_text(line)
    print(line)


if __name__ == "__main__":
    main()
