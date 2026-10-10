# Sandbox image used to install and probe MCP servers.
#
# Design constraints:
# - No host volume mounts other than a read-only /work for the install command.
# - Default network mode = none. The harness toggles bridge ONLY when the
#   server's manifest declares a network requirement and the operator has
#   explicitly approved it for that run.
# - Non-root user.
# - Drop all Linux capabilities. Add back only NET_BIND_SERVICE if needed.
# - Memory cap, pid cap, read-only root filesystem are set at run-time by the
#   Python harness, not here, so values can be tuned per-target.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NODE_VERSION=22 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg git build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g npm@latest

# uv + uvx (used by some Python MCP servers as the canonical install/run tool).
# Both binaries must be moved: `uvx` is a separate executable, not a uv subcommand.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /root/.local/bin/uvx /usr/local/bin/

RUN useradd --create-home --shell /bin/bash sandbox
WORKDIR /work
RUN chown sandbox:sandbox /work

# The probe script is mounted at runtime so we do not have to rebuild the
# image when the probe logic changes.
USER sandbox
CMD ["python", "/probe/probe.py"]
