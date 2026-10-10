from cym500.collectors.registries.base import RegistryAdapter
from cym500.collectors.registries.smithery import SmitheryAdapter
from cym500.collectors.registries.glama import GlamaAdapter
from cym500.collectors.registries.pulsemcp import PulseMcpAdapter
from cym500.collectors.registries.anthropic_servers import AnthropicServersAdapter

# composio (v1 API retired, HTTP 410; v3 requires an API key) and mcp.so (no
# public JSON API, HTML only) were verified dead on 2026-07-05 and dropped.
# The omission is documented in the thesis (ch05 registry-coverage note).
ADAPTERS: dict[str, type[RegistryAdapter]] = {
    "smithery": SmitheryAdapter,
    "glama": GlamaAdapter,
    "pulsemcp": PulseMcpAdapter,
    "anthropic-servers": AnthropicServersAdapter,
}

__all__ = ["RegistryAdapter", "ADAPTERS"]
