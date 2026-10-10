"""Typer CLI entrypoints for collection."""
from __future__ import annotations

import typer

from cym500.collectors import github_configs, registry_runner, tools_harvest
from cym500.common.logging import configure

collectors_app = typer.Typer(help="Phase 1 collection commands")


@collectors_app.callback()
def _setup() -> None:
    configure()


@collectors_app.command("github")
def github_cmd(config: str = "config/collectors.yaml") -> None:
    """Run GitHub code-search queries; redact and persist matching configs."""
    added = github_configs.collect(config_path=config)
    typer.echo(f"github: {added} new artefacts")


@collectors_app.command("registries")
def registries_cmd(config: str = "config/collectors.yaml") -> None:
    """Enumerate all configured registries; persist normalised server records."""
    counts = registry_runner.collect_all(config_path=config)
    for k, v in counts.items():
        typer.echo(f"{k}: {v} new records")


@collectors_app.command("registry-tools")
def registry_tools_cmd() -> None:
    """Flatten registry-served tool descriptions (Path 1) into tools.jsonl."""
    result = tools_harvest.harvest_registry_tools()
    typer.echo(
        f"registry tools: {result['tools']} tools from "
        f"{result['servers_with_tools']} servers"
    )


@collectors_app.command("all")
def all_cmd(config: str = "config/collectors.yaml") -> None:
    """Run github + registries."""
    github_cmd(config)
    registries_cmd(config)
