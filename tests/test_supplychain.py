"""Regression tests for the deterministic package extraction (axis A10).

The supply-chain concentration result in Chapter 4 is reported without coder
validation, so the extraction rule is pinned here: any change to the rule must
break a test rather than silently move a reported number.
"""
from cym500.analysis.supplychain import entry_package


# --- npm / npx --------------------------------------------------------------

def test_npx_skips_yes_flag_and_takes_package():
    assert entry_package(
        {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}
    ) == ("npm", "@modelcontextprotocol/server-filesystem")


def test_scope_is_preserved_and_version_stripped():
    assert entry_package(
        {"command": "npx", "args": ["-y", "@playwright/mcp@1.2.3"]}
    ) == ("npm", "@playwright/mcp")


def test_dist_tag_is_stripped():
    assert entry_package({"command": "npx", "args": ["@playwright/mcp@latest"]}) == (
        "npm",
        "@playwright/mcp",
    )


def test_unscoped_package_version_stripped():
    assert entry_package({"command": "npx", "args": ["mcp-remote@0.1.0"]}) == (
        "npm",
        "mcp-remote",
    )


def test_caret_and_tilde_ranges_stripped():
    assert entry_package({"command": "npx", "args": ["pkg@^1.0.0"]}) == ("npm", "pkg")
    assert entry_package({"command": "npx", "args": ["pkg@~2.1"]}) == ("npm", "pkg")


def test_package_flag_value_is_skipped_not_taken_as_package():
    # `-p <spec>` names the package to install; the operand after it is the
    # binary to run, so the first *non-flag, non-value* argument still wins.
    assert entry_package(
        {"command": "npx", "args": ["-p", "some-installer", "real-package"]}
    ) == ("npm", "real-package")


def test_windows_cmd_shim_and_path_prefix_recognised():
    assert entry_package({"command": "npx.cmd", "args": ["srv"]}) == ("npm", "srv")
    assert entry_package({"command": "/usr/local/bin/npx", "args": ["srv"]}) == (
        "npm",
        "srv",
    )


# --- python runners ---------------------------------------------------------

def test_uvx_is_pypi():
    assert entry_package({"command": "uvx", "args": ["mcp-server-git"]}) == (
        "pypi",
        "mcp-server-git",
    )


def test_uvx_from_flag_value_is_skipped():
    assert entry_package(
        {"command": "uvx", "args": ["--from", "git+https://x/y", "tool"]}
    ) == ("pypi", "tool")


# --- docker -----------------------------------------------------------------

def test_docker_image_after_run_with_tag_stripped():
    assert entry_package(
        {"command": "docker", "args": ["run", "--rm", "-i", "ghcr.io/org/img:1.4"]}
    ) == ("docker", "ghcr.io/org/img")


# --- entries that carry no package identity ---------------------------------

def test_local_path_launch_has_no_package():
    assert entry_package({"command": "node", "args": ["/opt/srv/index.js"]}) is None


def test_bare_interpreter_has_no_package():
    assert entry_package({"command": "python", "args": ["-m", "srv"]}) is None


def test_remote_url_entry_has_no_package():
    assert entry_package({"url": "https://example.com/mcp"}) is None


def test_runner_with_no_operand_is_unresolved():
    assert entry_package({"command": "npx", "args": ["-y"]}) is None


def test_missing_args_is_unresolved():
    assert entry_package({"command": "npx"}) is None


def test_non_string_args_are_ignored():
    assert entry_package({"command": "npx", "args": [None, 3, "srv"]}) == ("npm", "srv")


def test_docker_flag_values_are_not_images():
    """Values of -e/-v/--mount must be skipped, not read as the image."""
    assert entry_package({"command": "docker", "args": [
        "run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=${TOKEN}",
        "-v", "/tmp:/tmp", "--mount", "type=bind,src=/a,dst=/b", "mcp/github:1.0",
    ]}) == ("docker", "mcp/github")


def test_docker_non_run_subcommands_yield_nothing():
    for sub in (["exec", "-i", "mycontainer", "node", "x.js"], ["compose", "up"], ["attach", "c"]):
        assert entry_package({"command": "docker", "args": sub}) is None


def test_docker_registry_port_and_digest():
    assert entry_package({"command": "docker", "args": [
        "run", "localhost:5000/team/img@sha256:abc"]}) == ("docker", "localhost:5000/team/img")
    assert entry_package({"command": "docker", "args": [
        "run", "--env=A=1", "img:latest"]}) == ("docker", "img")


def test_paths_urls_and_index_values_are_not_packages():
    assert entry_package({"command": "uvx", "args": [
        "--index-url", "https://mirrors.example/pypi/simple/", "mcp-server-x"]}) == ("pypi", "mcp-server-x")
    assert entry_package({"command": "npx", "args": ["-y", "/Users/me/local-server"]}) is None
    assert entry_package({"command": "npx", "args": ["https://example.dev/registry.tgz"]}) is None


def test_pypi_version_specifier_stripped():
    assert entry_package({"command": "uvx", "args": ["awslabs.eks-mcp-server==0.1.31"]}) == (
        "pypi", "awslabs.eks-mcp-server")


def test_pinning_classes():
    from cym500.analysis.supplychain import entry_pinning

    def pin(cmd, *args):
        return entry_pinning({"command": cmd, "args": list(args)})

    assert pin("npx", "-y", "tavily-mcp@0.1.4") == "exact"
    assert pin("uvx", "awslabs.eks-mcp-server==0.1.31") == "exact"
    assert pin("npx", "@playwright/mcp@latest") == "floating"
    assert pin("npx", "@playwright/mcp@^0.0.48") == "range"
    assert pin("npx", "-y", "@modelcontextprotocol/server-filesystem") == "none"
    # An npm scope alone is not a version.
    assert pin("npx", "@scope/pkg") == "none"
    assert pin("docker", "run", "-i", "mcp/github@sha256:abc") == "exact"
    assert pin("docker", "run", "mcp/github:1.2") == "exact"
    assert pin("docker", "run", "mcp/github:latest") == "floating"
    assert pin("docker", "run", "mcp/github") == "none"
    assert pin("node", "server.js") is None


def test_top_n_reach_counts_distinct_configs_not_a_sum(monkeypatch):
    """A config registering two top packages is one victim, not two."""
    from types import SimpleNamespace

    from cym500.analysis import supplychain

    def cfg(cid, *pkgs):
        entries = [{"command": "npx", "args": ["-y", p]} for p in pkgs]
        return SimpleNamespace(id=cid, server_entries=entries)

    corpus = [cfg("a", "pkg-one", "pkg-two"), cfg("b", "pkg-one"), cfg("c", "pkg-two")]
    monkeypatch.setattr(
        supplychain, "JsonlStore",
        lambda _path: SimpleNamespace(read=lambda _cls: iter(corpus)),
    )
    r = supplychain.supply_chain_concentration(top_n=2)
    assert [p["configs"] for p in r["top_packages"]] == [2, 2]
    assert r["top_n_config_reach"] == 3  # not 2 + 2 = 4
