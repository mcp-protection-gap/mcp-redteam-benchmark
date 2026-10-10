from cym500.analysis.gateways import entry_gateway, gateway_routing


def test_docker_gateway_by_subcommand_and_by_image():
    assert entry_gateway({"command": "docker", "args": ["mcp", "gateway", "run"]}) == "docker-mcp-gateway"
    assert entry_gateway({"command": "docker", "args": ["run", "-i", "docker/mcp-gateway"]}) == "docker-mcp-gateway"


def test_benchmarked_gateways_by_package():
    assert entry_gateway({"command": "uvx", "args": ["mcp-gateway", "--plugin", "basic"]}) == "lasso"
    assert entry_gateway({"command": "uvx", "args": ["--from", "mcp-contextforge-gateway", "mcpgateway"]}) == "contextforge"


def test_transport_bridge_is_not_a_gateway():
    assert entry_gateway({"command": "/home/u/.local/bin/mcp-proxy", "args": ["http://127.0.0.1:8000/mcp"]}) == "mcp-proxy"


def test_ordinary_servers_and_names_do_not_match():
    assert entry_gateway({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}) is None
    # a server merely named after a gateway is not routed through one
    assert entry_gateway({"command": "node", "args": ["build/index.js"], "name": "gateway"}) is None


def test_counts_configurations_not_entries():
    cfg = {"server_entries": [{"command": "docker", "args": ["mcp", "gateway", "run"]}] * 3}
    assert gateway_routing([cfg, {"server_entries": []}]) == {
        "n_configs": 2, "per_gateway": {"docker-mcp-gateway": 1}}
