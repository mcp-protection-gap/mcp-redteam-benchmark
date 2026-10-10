"""Supply-chain concentration across client configurations (Chapter 4).

Axis A10. Recovers the package identity a server entry installs at launch and
measures how concentrated the resulting dependency set is. The question is
blast radius: if one published package were compromised, how much of the
measured population would it reach?

Extraction is deterministic (Tier 1). The package identity is read off the
declared `command` and `args` of a server entry under the rules in
`entry_package`; nothing is inferred from prose and no coder judgement is
involved. Entries that launch a local path, a bare interpreter, or a remote URL
carry no package identity and are reported as unresolved rather than guessed.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from cym500.common.schema import ConfigArtefact
from cym500.common.storage import JsonlStore, DATA_ROOT

OUT = Path(DATA_ROOT) / "results" / "posture"

# Runners that take a package specifier as their first non-flag argument.
_NODE_RUNNERS = ("npx",)
_PYTHON_RUNNERS = ("uvx", "pipx")

# Flags consumed by those runners before the package specifier appears.
_RUNNER_FLAGS = {"-y", "--yes", "-q", "--quiet", "-p", "--package", "--from"}
# Flags that take a value, which must also be skipped. `--from`/`--package` name
# the package in some invocations, but the value is then repeated or implied by
# the following operand, which is what is read.
_RUNNER_FLAGS_WITH_VALUE = {
    "-p", "--package", "--from", "--index-url", "--extra-index-url", "--index",
    "--default-index", "--with", "--python", "--registry",
}

# Trailing version specifier or dist-tag on a package spec. Anchored at the end
# so that a leading npm scope (@scope/name) is preserved.
_VERSION_SUFFIX = re.compile(
    r"@(?:[\^~><=v]*\d[\w.\-+]*|latest|next|beta|alpha|canary|rc|stable)$",
    re.I,
)


# PEP 440 specifier on a PyPI requirement (pkg==1.2, pkg>=1.0).
_PYPI_PIN = re.compile(r"(?:==|>=|<=|~=|!=|>|<).*$")


def _as_str(v: object) -> str:
    return v if isinstance(v, str) else ""


def _runner(command: str) -> str | None:
    """Classify the launch command, ignoring any path prefix or .cmd suffix."""
    base = command.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    base = base.removesuffix(".exe").removesuffix(".cmd")
    if base in _NODE_RUNNERS:
        return "npm"
    if base in _PYTHON_RUNNERS:
        return "pypi"
    if base == "docker":
        return "docker"
    return None


def _first_operand(args: list[str], skip: set[str]) -> str | None:
    """First argument that is neither a flag nor the value of a skipped flag."""
    expect_value = False
    for raw in args:
        a = _as_str(raw).strip()
        if not a:
            continue
        if expect_value:
            expect_value = False
            continue
        if a in _RUNNER_FLAGS_WITH_VALUE:
            expect_value = True
            continue
        if a in skip:
            continue
        if a.startswith("-"):
            continue
        return a
    return None


# `docker run` options that consume the following argument as their value. Their
# values (env assignments, mount specs, network names) must never be read as the
# image reference.
_DOCKER_RUN_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--network", "--net",
    "--name", "-p", "--publish", "-w", "--workdir", "-u", "--user", "--entrypoint",
    "--add-host", "-l", "--label", "-m", "--memory", "--cpus", "--platform",
    "--pull", "-h", "--hostname", "--device", "--cap-add", "--cap-drop",
    "--security-opt", "--tmpfs", "--ulimit", "--log-driver", "--log-opt",
    "--restart", "--runtime", "--gpus", "--ipc", "--pid", "--dns", "-a", "--attach",
}


def _docker_run_image(args: list[str]) -> str | None:
    """Image reference of a `docker run` invocation, or None.

    The first non-flag argument must be the `run` subcommand; `exec`, `compose`,
    `attach` and the like name a container or project rather than an image and
    yield None. After `run`, flags are skipped together with the value of any
    flag that takes one (`--flag=value` forms are a single argument), and the
    first remaining operand is the image.
    """
    it = iter([a.strip() for a in args if a.strip()])
    for a in it:
        if a.startswith("-"):
            continue
        if a != "run":
            return None
        break
    else:
        return None
    for a in it:
        if a in _DOCKER_RUN_VALUE_FLAGS:
            next(it, None)
            continue
        if a.startswith("-"):
            continue
        return a
    return None


def _strip_docker_tag(image: str) -> str:
    """Remove a digest (@sha256:...) or a :tag, keeping any registry host:port."""
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return image[: len(image) - len(last)] + last.split(":", 1)[0]
    return image


def entry_package(entry: dict) -> tuple[str, str] | None:
    """A10 package identity, read off declared fields. No coder judgement.

    Returns (ecosystem, package) or None when the entry installs nothing
    identifiable. The rule, in order:

    * `npx` (node) or `uvx`/`pipx` (python): the first argument that is not a
      flag, and not the value of a flag that takes one, is the package
      specifier. A trailing version or dist-tag is stripped; an npm scope is
      kept.
    * `docker`: the first operand after `run` is the image reference, recorded
      with its registry path intact and any `:tag` removed.
    * anything else (a local path, a bare `node`/`python`, a remote `url`
      entry): no package identity, so None.
    """
    command = _as_str(entry.get("command"))
    if not command:
        return None
    eco = _runner(command)
    if eco is None:
        return None
    args = [_as_str(a) for a in (entry.get("args") or []) if isinstance(a, str)]
    if eco == "docker":
        image = _docker_run_image(args)
        if not image:
            return None
        return ("docker", _strip_docker_tag(image))
    operand = _first_operand(args, _RUNNER_FLAGS)
    if not operand:
        return None
    # A local path, a URL or a tarball names no registry package.
    if operand.startswith(("/", ".", "~", "\\", "$")) or "://" in operand:
        return None
    pkg = _PYPI_PIN.sub("", _VERSION_SUFFIX.sub("", operand))
    return (eco, pkg) if pkg else None


_FLOATING_TAGS = {"latest", "next", "beta", "alpha", "canary", "rc", "stable", "main", "master", "edge"}


def entry_pinning(entry: dict) -> str | None:
    """How firmly an entry's package is pinned, read off the declared specifier.

    Returns None when the entry names no package (see `entry_package`), else:

    * ``exact``: an exact version (``pkg@1.2.3``, ``pkg==1.2.3``) or, for docker,
      a digest (``@sha256:``) or a non-floating tag;
    * ``floating``: a moving dist-tag or image tag such as ``@latest``;
    * ``range``: a version range (``^``, ``~``, ``>=``, ``x``) or an unexpanded
      variable;
    * ``none``: no version at all, so the registry's current release is taken.

    Only ``exact`` protects against a malicious release being pulled on the next
    launch, which is what the install-time provenance mitigation requires.
    """
    if entry_package(entry) is None:
        return None
    eco = _runner(_as_str(entry.get("command")))
    args = [_as_str(a) for a in (entry.get("args") or []) if isinstance(a, str)]
    if eco == "docker":
        image = _docker_run_image(args) or ""
        if "@sha256:" in image:
            return "exact"
        last = image.rsplit("/", 1)[-1]
        if ":" not in last:
            return "none"
        return "floating" if last.split(":", 1)[1].lower() in _FLOATING_TAGS else "exact"
    operand = _first_operand(args, _RUNNER_FLAGS) or ""
    if "==" in operand:
        return "exact"
    if re.search(r"(>=|<=|~=|>|<)", operand):
        return "range"
    m = re.search(r"(?<!^)@([^/@]+)$", operand)
    if not m:
        return "none"
    v = m.group(1)
    if v.lower() in _FLOATING_TAGS:
        return "floating"
    if re.match(r"[\^~><=*$]", v) or v.split(".")[-1].lower() in ("x", "*"):
        return "range"
    return "exact"


def supply_chain_concentration(top_n: int = 10) -> dict:
    """Package concentration over the configuration corpus.

    Reach is counted in distinct configurations rather than entries, because a
    compromised package reaches a victim once however many times that victim
    registers it.
    """
    configs = JsonlStore("processed/configs.jsonl")
    by_entry: Counter[str] = Counter()
    by_config: dict[str, set[str]] = defaultdict(set)
    by_eco: Counter[str] = Counter()
    n_configs = 0
    n_entries = 0
    n_resolved = 0
    configs_with_pkg = 0
    pinning: Counter[str] = Counter()

    for idx, c in enumerate(configs.read(ConfigArtefact)):
        n_configs += 1
        cid = c.id or f"_idx{idx}"
        seen_here = False
        for e in c.server_entries:
            if not isinstance(e, dict):
                continue
            n_entries += 1
            found = entry_package(e)
            if found is None:
                continue
            eco, pkg = found
            n_resolved += 1
            pinning[entry_pinning(e) or "none"] += 1
            by_entry[pkg] += 1
            by_eco[eco] += 1
            by_config[pkg].add(cid)
            seen_here = True
        if seen_here:
            configs_with_pkg += 1

    reach = Counter({p: len(s) for p, s in by_config.items()})
    top = reach.most_common(top_n)
    # Distinct configurations reached by any of the top packages: a config that
    # registers two of them is one victim, not two, so the reaches do not sum.
    top_reach = len(set().union(*(by_config[p] for p, _ in top)))
    singletons = sum(1 for _, n in reach.items() if n == 1)

    return {
        "n_configs": n_configs,
        "n_server_entries": n_entries,
        "n_resolved_entries": n_resolved,
        "n_configs_with_package": configs_with_pkg,
        "n_distinct_packages": len(reach),
        "by_ecosystem": dict(by_eco),
        "top_packages": [
            {"package": p, "configs": n, "entries": by_entry[p]} for p, n in top
        ],
        "top_n": top_n,
        "top_n_config_reach": top_reach,
        "max_single_package_reach": top[0][1] if top else 0,
        "n_singleton_packages": singletons,
        "pinning": dict(pinning),
    }
