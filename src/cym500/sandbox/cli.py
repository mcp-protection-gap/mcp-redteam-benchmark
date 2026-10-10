"""Typer CLI for the sandbox probe (Path 2)."""
from __future__ import annotations

import typer

from cym500.common.logging import configure
from cym500.sandbox import runner

sandbox_app = typer.Typer(help="Phase 1 sandbox probe commands")


@sandbox_app.callback()
def _setup() -> None:
    configure()


@sandbox_app.command("probe")
def probe_cmd(
    limit: int = typer.Option(None, help="Cap on installable servers to probe."),
    network: bool = typer.Option(
        False, help="Run on a bridge network so npx/uvx installs can fetch packages."
    ),
    command_prefix: str = typer.Option(
        None, "--command-prefix", help="Only probe install commands with this prefix (npx/uvx)."
    ),
    install_timeout: int = 60,
    probe_timeout: int = 120,
) -> None:
    """Install and probe the installable subset of servers.jsonl for tools/list."""
    result = runner.run(
        limit=limit,
        install_timeout=install_timeout,
        probe_timeout=probe_timeout,
        require_network=network,
        command_prefix=command_prefix,
    )
    typer.echo(
        f"probed {result['probed']}: {result['ok']} ok, {result['fail']} failed "
        f"(failures + stderr in data/processed/sandbox_failures.jsonl)"
    )
