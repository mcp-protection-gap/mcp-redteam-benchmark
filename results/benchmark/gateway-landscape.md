# Wider open-source in-path gateway landscape (survey, 2026-09-29)

Beyond the two gateways benchmarked (Lasso mcp-gateway, IBM ContextForge), several
more heavily starred open-source in-path gateways advertise content guardrails.
They were not benchmarked because, in their documented configurations, the
guardrails inspect the LLM-provider path or call an external/paid moderation
service, rather than masking the MCP tool surface itself. Evidence, verified from
each project's own repository (not vendor blogs):

## agentgateway (Solo.io / CNCF), Apache-2.0, ~5.1k stars
- `examples/llm-prompt-guard/config.yaml`: the `promptGuard` policy (regex,
  builtins `email`/`SSN`, `action: reject`) is nested under an `ai:` backend
  (`provider.openAI`), i.e. it guards LLM-provider traffic.
- `examples/mcp-basic/config.yaml`: the `mcp:` target (stdio `npx
  @modelcontextprotocol/server-everything`) carries only `cors`; the MCP example
  set covers auth / authz / cors / rate-limit, not content guardrails.
- Guardrail backends advertised: regex (local), plus OpenAI moderation, AWS
  Bedrock Guardrails, Google Model Armor, custom webhooks (external/paid).
- Conclusion: inspects no MCP tool content in its documented configuration.
- No macOS-Intel binary in the v1.5.0 release (darwin-arm64 and linux only), so
  an end-to-end run on the benchmark host was not possible without Docker; given
  the above it would measure zero MCP-content detection.

## Bifrost (maximhq), Apache-2.0, ~8.4k stars
- MCP docs (docs.getbifrost.ai/features/mcp): MCP support is tool discovery,
  filtering, and execution ("tool calls from LLMs are suggestions only;
  execution requires a separate API call"). No plugin (PreHook/PostHook)
  interception of MCP tool RESULTS is documented, so tool-output content
  inspection is not a documented capability.

## Higress (CNCF/Alibaba), Apache-2.0
- higress.ai: MCP is "MCP service hosting" with "protocol offloading, unified
  identity authentication, traffic scheduling, parameter mapping, security
  audit" (governance) and separate "Tool-call governance". Content safety
  (Qwen3Guard integration) is described on the AI/LLM path. Masking of MCP tool
  output content is not documented.

## Portkey Gateway, MIT (open source) + commercial platform, ~8k stars
- Portkey MCP gateway blog: "policies before requests reach LLMs or MCP
  servers" and "blocking risky tool calls" -- input/access-layer and governance.
  PII redaction / content filtering are described at that layer; filtering of
  MCP tool OUTPUTS (results returned from a tool) is not addressed.

## Governance/routing only (like the excluded shortlist)
Pomerium (~5k), Obot (~1k), Microsoft MCP Gateway (844), Docker mcp-gateway,
MCPProxy, FLUJO.

## Takeaway
Gateways that mask the MCP tool content itself, as Lasso and ContextForge do,
are the minority; most open-source "AI/MCP gateways" apply their content
guardrails to the LLM-provider surface or via external services.
