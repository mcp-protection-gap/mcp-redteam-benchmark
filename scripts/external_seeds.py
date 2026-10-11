"""Independent tool-poisoning seeds from published proofs of concept.

The corpus of Chapter 6 carries two tool-poisoning seeds written for this
study. This script assembles ten further seeds written by other authors, so a
deterministic product's result on the class does not rest on two payloads.

Sources, pinned by commit (neither repository carries a licence, so the texts
are fetched and not redistributed here):

* invariantlabs-ai/mcp-injection-experiments @ 7382a5e6
    direct-poisoning.py, shadowing.py, whatsapp-takeover.py
* harishsg993010/damn-vulnerable-MCP-server @ 79734c19
    challenges 2, 5 and 10 (the tools whose descriptions carry the injection)
* Trail of Bits, "Jumping the line" (21 April 2025), the one example description

Usage:
    python external_seeds.py fetch  <dir>            # download the sources
    python external_seeds.py build  <dir> > set.jsonl
    python external_seeds.py yara   set.jsonl        # Cisco mcp-scanner, YARA only

The sources are parsed statically (ast); nothing downloaded is executed.
"""
import ast
import html
import json
import os
import re
import subprocess
import sys
import tempfile

INV = "https://raw.githubusercontent.com/invariantlabs-ai/mcp-injection-experiments/7382a5e64d825b2c7c2bace11f8fb9f2f16e01e2/"
DV = "https://raw.githubusercontent.com/harishsg993010/damn-vulnerable-MCP-server/79734c19f5104cd11486c90926d245560f53befa/challenges/"
TOB = "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"
FILES = {
    "inv-direct-poisoning.py": INV + "direct-poisoning.py",
    "inv-shadowing.py": INV + "shadowing.py",
    "inv-whatsapp-takeover.py": INV + "whatsapp-takeover.py",
    "dvmcp-challenge2.py": DV + "easy/challenge2/server.py",
    "dvmcp-challenge5.py": DV + "medium/challenge5/server.py",
    "dvmcp-challenge10.py": DV + "hard/challenge10/server.py",
    "tob.html": TOB,
}
# (file, function, which docstring) -> seed. "assigned" = text later assigned to __doc__.
SEEDS = [
    ("inv-direct-poisoning.py", "add", "doc"),
    ("inv-shadowing.py", "add", "doc"),
    ("inv-whatsapp-takeover.py", "get_fact_of_the_day", "assigned"),
    ("dvmcp-challenge2.py", "get_company_data", "doc"),
    ("dvmcp-challenge2.py", "search_company_database", "doc"),
    ("dvmcp-challenge5.py", "calculate", "longest"),
    ("dvmcp-challenge5.py", "enhanced_calculate", "doc"),
    ("dvmcp-challenge10.py", "get_user_profile", "doc"),
    ("dvmcp-challenge10.py", "malicious_check_system_status", "doc"),
]


def fetch(d: str) -> None:
    os.makedirs(d, exist_ok=True)
    for name, url in FILES.items():
        subprocess.run(["curl", "-sSL", "-m", "30", "-o", os.path.join(d, name), url], check=True)


def _schema(fn: ast.FunctionDef) -> dict:
    props = {a.arg: {"type": "string"} for a in fn.args.args if a.arg not in ("self", "ctx")}
    return {"type": "object", "properties": props}


def _from_py(path: str, func: str, which: str) -> tuple[str, dict]:
    tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func]
    if which == "assigned":
        for n in ast.walk(tree):
            if (isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
                    and any(isinstance(t, ast.Attribute) and t.attr == "__doc__" for t in n.targets)):
                return n.value.value.strip(), _schema(fns[0])
        raise ValueError(f"no assigned docstring in {path}")
    fn = max(fns, key=lambda n: len(ast.get_docstring(n) or "")) if which == "longest" else fns[0]
    return (ast.get_docstring(fn) or "").strip(), _schema(fn)


def _tob(path: str) -> str:
    t = open(path, encoding="utf-8", errors="replace").read()
    i = t.find("Retrieve a description of this user")
    seg = html.unescape(re.sub(r"<[^>]+>", "", t[i:i + 3000]))
    end = "current IP address?"
    return seg[:seg.find(end) + len(end)].strip()


def build(d: str) -> list[dict]:
    out = []
    for fname, func, which in SEEDS:
        desc, schema = _from_py(os.path.join(d, fname), func, which)
        out.append((fname.split("-")[0], f"{fname[:-3]}::{func}", func, desc, schema, FILES[fname]))
    out.append(("tob", "tob-line-jumping::workstation_environment", "workstation_environment",
                _tob(os.path.join(d, "tob.html")), {"type": "object", "properties": {}}, TOB))
    cases = []
    for src, cid, func, desc, schema, url in out:
        assert len(desc) > 80, (cid, len(desc))
        cases.append({
            "case_id": f"tool_poisoning_ext::{cid}",
            "threat_class": "tool_poisoning",
            "target": "tool_description",
            "payload": {"tool_name": func, "description": desc, "input_schema": schema},
            "metadata": {"source": src, "url": url,
                         "oracle": {"expected": "block", "check": "scanner_blocks", "marker": desc[:24]}},
        })
    return cases


def yara(set_path: str) -> list[dict]:
    cases = [json.loads(l) for l in open(set_path)]
    tools = [{"name": f"t{i:03d}", "description": c["payload"]["description"],
              "inputSchema": c["payload"]["input_schema"]} for i, c in enumerate(cases)]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"tools": tools}, tf); tf.close()
    env = {k: v for k, v in os.environ.items() if k not in ("MCP_SCANNER_LLM_API_KEY", "MCP_SCANNER_API_KEY")}
    p = subprocess.run(["mcp-scanner", "--analyzers", "yara", "--format", "raw", "static", "--tools", tf.name],
                       capture_output=True, timeout=600, env=env)
    os.unlink(tf.name)
    raw = p.stdout.decode(errors="replace")
    data = json.loads(raw[raw.find("["):] if raw.lstrip()[:1] not in "[{" else raw)
    results = data if isinstance(data, list) else data.get("results") or data.get("scan_results") or []
    unsafe = {r.get("tool_name"): r for r in results if isinstance(r, dict) and not r.get("is_safe", True)}
    out = []
    for i, c in enumerate(cases):
        r = unsafe.get(f"t{i:03d}")
        ev = sorted({f.get("threat_type") or f.get("rule") or "" for a in ((r or {}).get("findings") or {}).values()
                     for f in (a.get("threat_names") and [{"threat_type": x} for x in a["threat_names"]] or [])}) if r else []
        out.append({"case_id": c["case_id"], "source": c["metadata"]["source"], "blocked": r is not None, "evidence": ";".join(ev)})
    return out


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "fetch":
        fetch(sys.argv[2])
    elif cmd == "build":
        for c in build(sys.argv[2]):
            sys.stdout.write(json.dumps(c) + "\n")
    elif cmd == "yara":
        for v in yara(sys.argv[2]):
            sys.stdout.write(json.dumps(v) + "\n")
