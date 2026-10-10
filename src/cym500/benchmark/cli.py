"""Typer CLI for Phase 3 benchmark."""
from __future__ import annotations

import typer

from cym500.benchmark.gateways import (
    NoGatewayAdapter,
    McpGatewayRegistryAdapter,
    MicrosoftAksGatewayAdapter,
    SoloIoAdapter,
)
from cym500.benchmark.comparators import CiscoYaraComparator, McpScanComparator
from cym500.benchmark.harness import run_benchmark
from cym500.common.logging import configure

benchmark_app = typer.Typer(help="Phase 3 benchmark commands")


_GATEWAYS = {
    "none": NoGatewayAdapter,
    "mcp-gateway-registry": McpGatewayRegistryAdapter,
    "ms-aks-mcp": MicrosoftAksGatewayAdapter,
    "solo-io": SoloIoAdapter,
    "mcp-scan": McpScanComparator,
    "mcp-scanner-yara": CiscoYaraComparator,
}


@benchmark_app.callback()
def _setup() -> None:
    configure()


@benchmark_app.command("run")
def run_cmd(gateway: str = "none", limit: int = 0, subdir: str = "") -> None:
    """Run the benchmark against one gateway. limit=0 means full corpus.

    subdir writes results under data/results/benchmark/<subdir>/ so a re-run
    never overwrites the reported results.
    """
    cls = _GATEWAYS.get(gateway)
    if not cls:
        raise typer.BadParameter(f"unknown gateway: {gateway}; one of {list(_GATEWAYS)}")
    if subdir:
        from cym500.benchmark import harness
        harness.RESULTS = harness.RESULTS / subdir
    out = run_benchmark(cls(), corpus_limit=(limit or None))
    typer.echo(typer.style(f"\n== {gateway} ==", bold=True))
    typer.echo(f"TPR: {out['tpr']:.3f}    FPR: {out['fpr']:.3f}")
    for cls_name, v in out["per_class_tpr"].items():
        typer.echo(f"  {cls_name}: TPR={v:.3f}")
