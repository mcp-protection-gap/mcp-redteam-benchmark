# In-path gateway benchmark (Lasso mcp-gateway)

This harness benchmarks a real, deployable **in-path** open-source MCP gateway
against the Chapter 6 red-team corpus and the Chapter 7 benign baseline, on the
same terms as the two static content scanners. It closes the gap Chapter 7
otherwise records: that no in-path gateway could be benchmarked.

## What it does

It stands up, per case:

```
MCP client  ->  mcp-gateway (Lasso, all free plugins)  ->  stub MCP server
```

The stub (`stub_server.py`) serves exactly the tool definition, tool output or
sampling request the case carries. `inpath_probe.py` drives a genuine MCP client
through the gateway, lists tools (did the gateway's scanner block the server?)
and, if a tool survives, calls it (was the request or output masked, or the call
refused?). `run_inpath.py` scores each case from what the gateway **forwarded to
the client**, using the case's own oracle marker.

The gateway runs with every free plugin enabled, as a practitioner would obtain
it out of the box:

```
mcp-gateway --mcp-json-path <cfg> --scan --plugin basic --plugin presidio
```

- `--scan`: the tool-description security scanner (blocks a server whose tool
  description trips its patterns).
- `basic`: local secret masking in tool-call arguments and outputs.
- `presidio`: local PII / entity masking (needs the spaCy `en_core_web_lg` model).

No paid plugin (Lasso's cloud injection detector) is used.

## Setup (separate venv: the gateway pins `mcp<2`)

```sh
uv venv lasso --python 3.12
VIRTUAL_ENV=lasso uv pip install "mcp-gateway[presidio]==1.2.1" "mcp<2"
SSL_CERT_FILE=$(lasso/bin/python -m certifi) \
  VIRTUAL_ENV=lasso lasso/bin/python -m spacy download en_core_web_lg
```

## Run

```sh
PY=lasso/bin/python
# 77 attack cases
$PY run_inpath.py --corpus <repo>/project/data/processed/redteam_corpus.jsonl \
    --out attack-verdicts.jsonl --py $PY
# 500 benign definitions (false-positive rate)
$PY run_inpath.py --corpus <repo>/project/data/raw/benign/harvested_tools.jsonl \
    --out benign-verdicts.jsonl --py $PY --benign
```

`SSL_CERT_FILE` must point at certifi's bundle (`$PY -m certifi`) or the gateway
subprocess cannot verify TLS. The gateway's stderr must go to a file, not a
closed pipe (the harness does this): a large teardown traceback to a closed pipe
raises SIGPIPE and loses the result.

## Scoring conventions

- **tool_poisoning / schema_poisoning** (payload in the definition): blocked iff
  the scanner blocked the server or the tool did not surface.
- **cross_server_exfil / prompt_injection_via_output** (payload in a tool
  output): blocked iff the gateway inserted a redaction placeholder
  (`<JWT_TOKEN>`, `<IP_ADDRESS>`, …). A mutated marker that no longer appears
  verbatim does **not** count as blocked — the payload still passed.
- **sampling_injection**: blocked iff the gateway did not relay the
  server-initiated `sampling/createMessage` request.
- **rug_pull**: temporal. The gateway scans once at startup, and a rug pull's
  malice appears only after approval, so a realistic deployment scans the benign
  pre-approval version (matching the Chapter 7 convention for the static
  scanners). Recorded not-caught, with whether the scanner *would* flag the
  post-approval version noted separately (`scanner_would_flag_post_version`).
- **supply_chain / credential_leakage**: out of a gateway's runtime surface (a
  package manifest / server source is never in the MCP message path).

## The masking demonstration

The 77 corpus markers are not real secrets, so the corpus score does not
exercise the gateway's secret/PII masking. `masking-demo.json` records a
separate targeted probe: a tool whose output carries a real-shaped JWT and an
RFC 1918 endpoint is masked to `<JWT_TOKEN>` and `<IP_ADDRESS>` in transit —
the two harms measured in Chapter 4.

## The scored secret-in-output set (replaces the one-off masking probe)

`masking_set.py` generates six benign tools whose **output** carries a synthetic,
non-functional but correctly shaped secret or private endpoint (a dead JWT, a
`ghp_` dummy, a `xoxb-` dummy, AWS's documented `AKIAIOSFODNN7EXAMPLE`, a `AIza`
GCP key, an RFC 1918 endpoint). Run it through `run_inpath.py` like the corpus.
The gateway masked 5 of 6; the Slack bot token passed because the `basic` plugin
carries the `xapp-` app-token shape but not `xoxb-`. The no-gateway control
forwards all six unchanged; the two pre-deployment scanners never see a tool
output. Results: `secret-in-output-verdicts.jsonl`.

## Second in-path gateway: IBM ContextForge (plugin-layer)

ContextForge is a full HTTP+DB gateway; its content detection lives in the
`cpex_pii_filter` plugin (pip: `cpex-pii-filter`). `run_contextforge.py` runs
that real plugin through its own `tool_post_invoke` hook on the secret-in-output
set (a plugin-layer evaluation, distinct from Lasso's end-to-end run; the plugin
is the content-detection component, so the masking comparison is fair). Setup:

```sh
uv venv cf --python 3.12
VIRTUAL_ENV=cf uv pip install mcp-contextforge-gateway==1.0.11 cpex-pii-filter==0.3.9
cf/bin/python run_contextforge.py --set <masking_set.jsonl> --out cf-verdicts.jsonl
```

Result: masks 1/6 (the private endpoint only). Its Rust detector supports
classic PII (email, ip_address, ssn, credit_card, phone) but not credential /
token shapes, even with detect_aws_keys / detect_api_key / detect_jwt set. So
the two gateways mask disjoint halves of the Phase 1 disclosure harm: Lasso the
credentials, ContextForge the endpoint. Results:
`data/results/benchmark/inpath-contextforge/`.
