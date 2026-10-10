# MCP Security: red-team corpus and benchmark results

Artefacts accompanying the MSc dissertation *Measuring MCP Security: Empirical
Risk Characterisation and the Protection Gap* (Royal Holloway, University of
London, Information Security Group, October 2026).

This repository is self-contained. It is the **public** half of the release. What is deliberately held
back, and until when, is stated under "Not included" below.

## Contents

```
corpus/
  redteam_corpus.jsonl        77 attack cases across 8 MCP threat classes
results/benchmark/
  none.json                   no-gateway control (aggregate)
  mcp-scan.json               Snyk Agent Scan (aggregate)
  mcp-scanner-yara.json       Cisco mcp-scanner, YARA analyzer (aggregate)
  *-verdicts.jsonl            per-case verdicts: case id, blocked, evidence, latency
  rerun-2026-09/              later re-run of the cloud scanner; its verdicts differ
                              from the reported run (dissertation Section 7.7)
results/adjudication/
  hygiene-adjudication.csv    written-rule adjudication of the four hygiene flags
  agent-scan-code-split-*.json  rater-free check on scanner false positives
  reference-servers-probe.json  the seven Anthropic reference servers, probed
                              after the corpus was frozen (dissertation App. C)
src/cym500/                   the pipeline: collectors, classification,
                              red-team generator, benchmark harness, analysis
tests/                        102 regression tests pinning the extraction rules
                              and the corpus generator
scripts/                      phase runners
config/collectors.yaml        the six GitHub code-search queries used
config/secret_verification.csv  placeholder / credential verdict per secret finding
                              (hash prefix only, no values)
pyproject.toml                dependencies and package metadata
```

## Running it

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
DATA_ROOT=./data python -m pytest tests -q     # 100 passed, 2 skipped
```

One skipped test requires a Docker daemon for the sandbox probe. The other
checks that no attack marker occurs in the 500-definition benign baseline, which
is held back with the raw harvest (see "Not included") and so is absent here.

To regenerate the corpus from its fixed seeds and confirm it reproduces
byte-identically, and to replay the benchmark against it, use the `redteam` and
`benchmark` modules. The collectors under `src/cym500/collectors/` are included
for completeness and for audit of how the measurement was performed; running
them performs live network collection against GitHub and public registries and
requires your own credentials (see `.env.example`). Do not run them without
reading the ethics and disclosure sections of the dissertation first.

### A note for anyone pushing this to GitHub

`tests/test_redaction.py` contains deliberately fake credentials as fixtures,
including a string in GitHub personal-access-token format. They are synthetic
(the token body is the alphabet followed by the digits) and grant access to
nothing, but they exist precisely because the redaction detector must catch that
shape, and GitHub push protection may flag them. They are test data, not a leak.

### The red-team corpus

77 cases covering tool poisoning, full-schema poisoning, rug pull, cross-server
exfiltration, indirect injection via tool output, sampling-based injection,
credential leakage and supply-chain compromise.

Every case is **synthetic**. No case contains a real credential, a real private
endpoint, or any material harvested from a third party. Each is generated
deterministically from a fixed seed by one of five mutation operators
(obfuscation, paraphrase, slow-drip, split-payload, Unicode-dressing), so the
corpus regenerates byte-identically rather than depending on a model sample.

One record per line. Fields: `case_id`, `threat_class`, `variant_id`, `target`,
`payload`, `description`, `expected_outcome`, `derived_from`, `metadata`
(including `mutation` and the per-case `oracle`).

The oracle decides whether a response counts as a successful block. Three
correctness properties are asserted of the corpus and enforced as unit tests:
coverage (every class has at least one executable case), oracle correctness
(every case has a well-formed oracle, an expected verdict of `block` and a
non-empty malicious marker), and benign-baseline sanity (no attack oracle fires
on a benign definition).

### Benchmark results

Aggregate detection rate, false-positive rate against a 500-definition benign
baseline, and per-tool latency, plus per-case verdicts keyed by `case_id`.

The benign baseline is drawn from tool descriptions published by public MCP
registries. Those descriptions are third-party content, so they are not
redistributed in bulk here. A verdict row keeps the full `tool_definition` only
where the scanner **flagged** the tool, which is what allows the false-positive
finding to be checked independently, and that is the release commitment the
dissertation makes. For unflagged benign cases the definition is omitted and the
row carries `tool_definition_omitted` together with the `derived_from`
identifier, from which the description can be re-fetched from the originating
registry. The verdicts, rates and latencies are unaffected.

## Not included, and why

**The measurement corpus is not in this repository.** The dissertation measured
1,916 public MCP client configurations, 605 registry-listed servers and 3,887
tool descriptions, and 13 of those configurations carry a high-confidence live
credential (12 distinct; five further shaped matches were verified documentation
placeholders and excluded).

Those records are withheld until the responsible-disclosure window for each
finding has closed. At the time of writing no notification had been issued and
so no ninety-day window had begun. Publishing the configuration records now
would identify the affected repositories before their maintainers have been
contacted, which is precisely what the disclosure policy exists to prevent.

When the corpus is deposited, per the policy stated in the dissertation:

- each secret finding is represented only by kind, detector, salted SHA-256 hash
  and a short preview, never the credential;
- no per-record identifying detail is published for a finding whose window is
  still open;
- a finding still unresolved after its window closes has its artefact
  anonymised rather than named;
- aggregate statistics are published as counts only, and the raw harvest is
  never released.

Redaction is applied at ingest, before any disk write, so no raw secret exists
in stored form to release.

## Reproducing

The corpus regenerates from fixed seeds and the benchmark replays against it.
The regression tests pin the generator, so a change to a mutation operator
breaks a test rather than silently altering a published case. The extraction
rules behind every reported figure are pinned the same way.

What can be reproduced falls into three tiers:

1. **Offline, from this release.** Regenerate the 77-case corpus byte-identically
   from its seeds, and run the full test suite that pins the generator and the
   extraction rules:
   ```sh
   DATA_ROOT=./data python -m pytest tests -q
   python -m cym500 redteam build   # rewrites the corpus deterministically
   ```
2. **Benchmark replay (needs the tools installed).** The per-case verdicts under
   `results/benchmark/` were produced by the two pre-deployment scanners and the
   two in-path gateways. Re-running them installs each product as shipped:
   `pip install snyk-agent-scan==0.5.15 cisco-ai-mcp-scanner==4.7.7` for the
   scanners (Agent Scan also needs `SNYK_TOKEN`, and its verdicts come from
   Snyk's service, so they can differ between runs); the
   in-path gateways (Lasso `mcp-gateway`, IBM ContextForge) via the harness in
   `scripts/inpath/` (see its README; each runs in its own `mcp<2` / gateway
   virtualenv). The `secret-in-output` set and its per-gateway masking verdicts
   regenerate with `scripts/inpath/masking_set.py`.
3. **Phase-1 measurement (data withheld).** The dataset-level figures (leaked
   secrets, private endpoints, transport/auth posture, supply-chain
   concentration, tool-description hygiene) are computed by the code under
   `src/cym500/` over the harvested corpus, which is **not** part of this public
   release: it is held back under the disclosure policy above. The full
   collection and analysis pipeline is included for audit, and the analysis
   (`python -m cym500 analyze posture`) reproduces every Phase-1 number when run
   against the private processed corpus.

## Licence

- The author's own contributions, namely the red-team corpus, the mutation
  operators and oracles, the benchmark metrics and all derived statistics:
  Creative Commons Attribution 4.0 International (CC BY 4.0).
- Accompanying software, where distributed with these artefacts: MIT.
- Retained third-party tool descriptions (the flagged benign definitions) remain
  the property of their respective publishers and are reproduced here only as
  evidence for the false-positive analysis. They are not covered by the CC BY
  grant above.

## Citing

Please cite the dissertation. A DOI is minted at the point of formal deposit,
which follows the close of the disclosure window; until then, cite this
repository by URL and commit.

## Responsible use

The corpus contains working attack payloads for the Model Context Protocol. It
is published so that MCP security tooling can be evaluated on a common,
reproducible basis. Use it against systems you own or are authorised to test.
