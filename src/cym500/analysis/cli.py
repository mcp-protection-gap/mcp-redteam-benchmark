"""Typer CLI for Phase 1 analysis aggregation."""
from __future__ import annotations

import json

import typer

from cym500.analysis import posture
from cym500.common.logging import configure

analyze_app = typer.Typer(help="Phase 1 analysis / aggregation commands")


@analyze_app.callback()
def _setup() -> None:
    configure()


@analyze_app.command("posture")
def posture_cmd() -> None:
    """Aggregate server posture + tool hygiene + config findings into results/posture/."""
    out = posture.write_all()
    typer.echo(json.dumps(out, indent=2))
