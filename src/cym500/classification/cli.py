"""Typer CLI for classification."""
from __future__ import annotations

import typer

from cym500.classification import labeler, kappa
from cym500.common.logging import configure

classify_app = typer.Typer(help="Phase 1 classification commands")


@classify_app.callback()
def _setup() -> None:
    configure()


@classify_app.command("auto")
def auto_cmd(out: str = "labels/auto.csv") -> None:
    n = labeler.auto_label(out_path=out)
    typer.echo(f"auto-labelled {n} tools")


@classify_app.command("review-queue")
def review_cmd(out: str = "labels/review_queue.csv") -> None:
    n = labeler.review_queue(out_path=out)
    typer.echo(f"queued {n} tools for human review")


@classify_app.command("kappa")
def kappa_cmd(a: str = "labels/coderA.csv", b: str = "labels/coderB.csv") -> None:
    out = kappa.per_label_kappa(coder_a=a, coder_b=b)
    for k, v in out.items():
        typer.echo(f"{k}: {v:.3f}" if v == v else f"{k}: NaN")
