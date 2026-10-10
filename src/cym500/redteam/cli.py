"""Typer CLI for red-team corpus."""
from __future__ import annotations

import typer

from cym500.common.logging import configure
from cym500.redteam import corpus

redteam_app = typer.Typer(help="Phase 2 red-team commands")


@redteam_app.callback()
def _setup() -> None:
    configure()


@redteam_app.command("build")
def build_cmd() -> None:
    n = corpus.build()
    typer.echo(f"built {n} attack cases")
