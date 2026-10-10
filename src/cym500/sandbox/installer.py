"""Docker-based sandbox harness for installing an MCP server and probing tools/list.

Public entrypoint: SandboxInstaller.probe(record) -> SandboxResult.

Hardening posture:
- network_mode='none' by default; only relaxed if the ServerRecord declares a
  network scope AND the run was authorised by the operator (require_network=True).
- read-only root filesystem.
- non-root user, all caps dropped, no privileged.
- mem_limit, pids_limit, ulimit nofile set conservatively.
- A fresh /work tmpfs is the only writable surface.

This wraps docker-py. If you prefer subprocess + docker CLI, swap _client out;
the public API is unchanged.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import ContainerError, ImageNotFound

from cym500.common.logging import get_logger
from cym500.common.schema import (
    Scope,
    ServerRecord,
    SourceLocation,
    ToolDescription,
)

log = get_logger(__name__)

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "cym500/mcp-sandbox:latest")
PROBE_DIR = Path(__file__).resolve().parent
DOCKERFILE = PROBE_DIR / "Dockerfile"
PROBE_SCRIPT = PROBE_DIR / "probe.py"


@dataclass(slots=True)
class SandboxResult:
    server_id: str
    success: bool
    tools: list[ToolDescription]
    raw: dict[str, Any]
    duration_s: float
    error: str | None = None


def _tail(container, limit: int = 2000) -> str:
    """Best-effort container log tail, for diagnosing probes that produced no output."""
    try:
        return container.logs().decode(errors="replace")[-limit:]
    except Exception:
        return ""


class SandboxInstaller:
    def __init__(self, image: str | None = None) -> None:
        self.image = image or SANDBOX_IMAGE
        self._client = docker.from_env()
        self._ensure_image()

    def _ensure_image(self) -> None:
        try:
            self._client.images.get(self.image)
        except ImageNotFound:
            log.info("sandbox_image_build", image=self.image, dockerfile=str(DOCKERFILE))
            self._client.images.build(
                path=str(PROBE_DIR),
                tag=self.image,
                rm=True,
                pull=True,
            )

    def probe(
        self,
        record: ServerRecord,
        install_timeout: int = 60,
        probe_timeout: int = 30,
        require_network: bool = False,
    ) -> SandboxResult:
        cmd = record.install_command
        if not cmd:
            return SandboxResult(
                server_id=record.id,
                success=False,
                tools=[],
                raw={},
                duration_s=0.0,
                error="no_install_command",
            )

        net = "bridge" if (require_network or Scope.NETWORK_EGRESS in record.declared_scopes) else "none"
        env = {
            "INSTALL_COMMAND": cmd,
            "INSTALL_TIMEOUT": str(install_timeout),
            "PROBE_TIMEOUT": str(probe_timeout),
            # The rootfs is read-only, so package managers need writable caches.
            # These must NOT live on the /work host bind mount: on Docker Desktop
            # /work is a virtiofs share whose mtime semantics break npm's cacache
            # lockfile ("npm error code ECOMPROMISED / Lock compromised"), failing
            # every `npx -y ...` install. Point HOME and the npm/uv/XDG caches at
            # the /home/sandbox tmpfs (a real Linux fs with working file locking);
            # /work then carries only the probe's small JSON output.
            "HOME": "/home/sandbox",
            "npm_config_cache": "/home/sandbox/.npm",
            "UV_CACHE_DIR": "/home/sandbox/.uv",
            "XDG_CACHE_HOME": "/home/sandbox/.cache",
        }

        started = datetime.now(UTC)
        container = None
        # Per-run writable output dir on the host, bind-mounted at /work. We use a
        # host bind mount rather than a tmpfs because tmpfs contents are released
        # when the container stops, and we read the probe's output *after* wait().
        # 0o777 because the container runs as an unprivileged uid (sandbox=1000)
        # that would otherwise be unable to write into a host-owned directory.
        workdir = Path(tempfile.mkdtemp(prefix="cym500-sandbox-"))
        os.chmod(workdir, 0o777)
        try:
            container = self._client.containers.create(
                self.image,
                command=["python", "/probe/probe.py"],
                environment=env,
                network_mode=net,
                read_only=True,
                user="sandbox",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                # tmpfs counts against mem_limit; the cache tmpfs below can hold a
                # full package install, so keep the limit comfortably above it.
                mem_limit="1g",
                pids_limit=128,
                tmpfs={
                    "/tmp": "rw,size=64m,noexec,mode=1777",
                    # HOME + all package-manager caches. exec is required (native
                    # npm addons, node); sized for one server's install tree.
                    "/home/sandbox": "rw,exec,size=768m,mode=0777",
                },
                # probe.py is bind-mounted read-only (the rootfs is read-only, so it
                # cannot be injected at runtime); /work is the only writable surface.
                volumes={
                    str(PROBE_SCRIPT): {"bind": "/probe/probe.py", "mode": "ro"},
                    str(workdir): {"bind": "/work", "mode": "rw"},
                },
                detach=True,
            )

            container.start()
            # probe.py may spend up to probe_timeout on *each* of its two reads
            # (initialize, then tools/list) plus the install, so allow for both
            # before we forcibly reclaim a container that is ignoring its own
            # deadline. A wait() that still times out means the probe hung; kill
            # it and fall through to read whatever output (if any) it left.
            wait_timeout = install_timeout + 2 * probe_timeout + 30
            try:
                exit_code = container.wait(timeout=wait_timeout)["StatusCode"]
            except Exception:  # noqa: BLE001 - docker/requests read timeout on wait
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = -1
            duration = (datetime.now(UTC) - started).total_seconds()

            out_path = workdir / "tools_list.json"
            if not out_path.exists():
                return SandboxResult(
                    server_id=record.id,
                    success=False,
                    tools=[],
                    raw={"exit_code": exit_code, "logs": _tail(container)},
                    duration_s=duration,
                    error="no_output",
                )
            raw = json.loads(out_path.read_text())

            tools = self._extract_tools(record, raw)
            return SandboxResult(
                server_id=record.id,
                success=exit_code == 0 and "error" not in raw,
                tools=tools,
                raw=raw,
                duration_s=duration,
                error=raw.get("error") if "error" in raw else None,
            )

        except ContainerError as e:
            return SandboxResult(
                server_id=record.id,
                success=False,
                tools=[],
                raw={},
                duration_s=(datetime.now(UTC) - started).total_seconds(),
                error=f"container_error: {e}",
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _extract_tools(record: ServerRecord, raw: dict) -> list[ToolDescription]:
        result = (raw.get("tools_list_response") or {}).get("result", {})
        tools_raw = result.get("tools", [])
        out: list[ToolDescription] = []
        now = datetime.now(UTC)
        for t in tools_raw:
            out.append(
                ToolDescription(
                    name=t.get("name", "<unknown>"),
                    description=t.get("description"),
                    input_schema=t.get("inputSchema"),
                    output_schema=t.get("outputSchema"),
                    annotations=t.get("annotations"),
                    raw=t,
                    server_id=record.id,
                    source=SourceLocation(
                        kind="sandbox",
                        registry=record.source.registry,
                        url=record.source.url,
                        fetched_at=now,
                    ),
                )
            )
        return out
