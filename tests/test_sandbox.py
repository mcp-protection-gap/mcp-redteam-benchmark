"""End-to-end sandbox harness test. Gated on a reachable Docker daemon.

Regression cover for the create/inject/retrieve path in SandboxInstaller.probe,
which is only exercised when Docker is present. It guards against:
  * running exec on a not-yet-started container,
  * the /work tmpfs being root-owned (non-root probe cannot write), and
  * reading probe output from a tmpfs that is released on container stop.
"""
import shlex
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cym500.common.schema import ServerRecord, SourceLocation

docker = pytest.importorskip("docker")

FIXTURE = Path(__file__).parent / "fixtures" / "stub_mcp_server.py"


def _docker_available() -> bool:
    try:
        docker.from_env().ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon not reachable"
)


def test_probe_discovers_stub_tools():
    from cym500.sandbox.installer import SandboxInstaller

    rec = ServerRecord(
        id="stub",
        name="stub",
        install_command="python -c " + shlex.quote(FIXTURE.read_text()),
        source=SourceLocation(kind="sandbox", fetched_at=datetime.now(UTC)),
    )
    result = SandboxInstaller().probe(rec, install_timeout=30, probe_timeout=15)

    assert result.success, f"probe failed: {result.error}"
    assert {t.name for t in result.tools} == {"echo", "add"}
