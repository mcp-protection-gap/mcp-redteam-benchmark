"""Evaluate ContextForge's pii_filter plugin on the secret-in-output set.

ContextForge is a full HTTP+DB gateway; its content detection lives in the
cpex_pii_filter plugin, invoked at the tool_post_invoke hook. This driver runs
that real plugin, through its own hook, on each case's tool output and reports
whether the marker survived. It is a plugin-layer evaluation (the gateway's
content-detection component exercised directly through its hook), distinct from
the end-to-end in-path run done for Lasso; the fidelity difference is stated in
the write-up.
"""
import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

from cpex.framework import (PluginConfig, PluginContext, GlobalContext,
                            ToolPostInvokePayload, PluginMode)
from cpex_pii_filter.pii_filter import PIIFilterPlugin

CONFIG = {
    "detect_ssn": True, "detect_credit_card": True, "detect_email": True,
    "detect_phone": True, "detect_ip_address": True, "detect_aws_keys": True,
    "detect_api_key": True, "detect_jwt": True, "detect_token": True,
    "detect_password": True, "default_mask_strategy": "partial",
    "block_on_detection": False, "log_detections": False,
}


def make_plugin():
    cfg = PluginConfig(
        name="pii", description="pii", author="bench",
        kind="cpex_pii_filter.pii_filter.PIIFilterPlugin", version="1.0",
        hooks=["tool_post_invoke"], mode=PluginMode.SEQUENTIAL, priority=10,
        config=CONFIG,
    )
    return PIIFilterPlugin(cfg)


async def run(cases):
    plugin = make_plugin()
    ctx = PluginContext(global_context=GlobalContext(request_id="bench"))
    out = []
    for c in cases:
        marker = c["metadata"]["oracle"]["marker"]
        text = c["payload"]["output"]
        payload = ToolPostInvokePayload(name=c["payload"]["tool"], result=text)
        res = await plugin.tool_post_invoke(payload, ctx)
        forwarded = text
        if getattr(res, "modified_payload", None) is not None:
            forwarded = res.modified_payload.result
        forwarded_s = forwarded if isinstance(forwarded, str) else json.dumps(forwarded)
        masked = marker not in forwarded_s
        out.append({"case_id": c["case_id"], "kind": c["case_id"].split("::")[1],
                    "blocked": masked, "mechanism": "pii-masked" if masked else "passed"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cases = [json.loads(l) for l in Path(a.set).read_text().splitlines() if l.strip()]
    res = asyncio.run(run(cases))
    Path(a.out).write_text("\n".join(json.dumps(r) for r in res) + "\n")
    masked = sum(r["blocked"] for r in res)
    for r in res:
        print(f"  {r['kind']:16} {r['mechanism']}", file=sys.stderr)
    print(f"masked {masked}/{len(res)}", file=sys.stderr)


if __name__ == "__main__":
    main()
