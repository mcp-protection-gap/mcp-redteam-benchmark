"""Regression tests for the deterministic config-level extraction (axes A1/A2).

These axes are reported without coder validation, so the extraction rule is
pinned here: any change to the rule must break a test rather than silently
move a number in Chapter 4.
"""
from cym500.analysis.posture import (
    entry_auth,
    entry_consent_bypass,
    entry_transport,
)
from cym500.analysis.stride import stride_for_config


# --- A1 transport -----------------------------------------------------------

def test_declared_type_wins_over_launch_shape():
    assert entry_transport({"type": "sse", "command": "npx"}) == "sse"


def test_streamable_http_variants_normalise_to_http():
    assert entry_transport({"type": "streamableHttp"}) == "http"
    assert entry_transport({"type": "streamable-http"}) == "http"


def test_command_implies_stdio():
    assert entry_transport({"command": "npx", "args": ["-y", "srv"]}) == "stdio"


def test_bare_url_implies_remote():
    assert entry_transport({"url": "https://example.test/mcp"}) == "remote_unspecified"


def test_neither_command_nor_url_is_undeterminable():
    assert entry_transport({"name": "orphan"}) == "undeterminable"


def test_transport_field_is_read_as_well_as_type():
    assert entry_transport({"transport": "stdio"}) == "stdio"


# --- A2 auth posture --------------------------------------------------------

def test_authorization_header_is_header_auth():
    assert entry_auth({"headers": {"Authorization": "Bearer x"}}) == "header_auth"


def test_credential_named_env_var_is_env_credential():
    assert entry_auth({"env": {"GITHUB_TOKEN": "x"}}) == "env_credential"
    assert entry_auth({"env": {"API_KEY": "x"}}) == "env_credential"


def test_non_credential_env_is_distinguished():
    assert entry_auth({"env": {"LOG_LEVEL": "debug"}}) == "env_no_credential"


def test_no_env_and_no_headers_is_none_declared():
    assert entry_auth({"command": "npx"}) == "none_declared"


def test_malformed_headers_do_not_raise():
    # Harvested configs are user-authored; headers is not always an object.
    assert entry_auth({"headers": "Authorization: Bearer x"}) == "none_declared"


# --- consent bypass ---------------------------------------------------------

def test_auto_approve_and_always_allow_detected():
    assert entry_consent_bypass({"autoApprove": ["read_file"]})
    assert entry_consent_bypass({"alwaysAllow": ["exec"]})


def test_empty_approve_list_is_not_a_bypass():
    assert not entry_consent_bypass({"autoApprove": []})
    assert not entry_consent_bypass({"command": "npx"})


# --- STRIDE join ------------------------------------------------------------

def test_secret_leak_maps_to_disclosure_and_elevation():
    assert stride_for_config(["secret_leak"]) == {
        "Information disclosure",
        "Elevation of privilege",
    }


def test_consent_bypass_maps_to_elevation_and_repudiation():
    assert stride_for_config(["consent_bypass"]) == {
        "Elevation of privilege",
        "Repudiation",
    }


def test_unknown_condition_contributes_nothing():
    assert stride_for_config(["not_a_condition"]) == set()


def test_conditions_union_rather_than_double_count():
    out = stride_for_config(["secret_leak", "private_endpoint"])
    assert out == {"Information disclosure", "Elevation of privilege"}


# --- condition co-occurrence ------------------------------------------------
# The co-occurrence table in Chapter 4 is reported without coder validation, so
# the counting rule is pinned here: a config is counted once per distinct pair
# of conditions it exhibits, and "clean" means it exhibits none.

def test_condition_count_partitions_the_corpus():
    """Every config falls in exactly one condition-count bucket."""
    from cym500.analysis.posture import config_findings

    f = config_findings()
    assert sum(f["condition_count"].values()) == f["n_configs"]
    assert f["n_clean"] == f["condition_count"].get("0", 0)


def test_multi_condition_total_matches_buckets():
    from cym500.analysis.posture import config_findings

    f = config_findings()
    expected = sum(v for k, v in f["condition_count"].items() if int(k) >= 2)
    assert f["n_multi_condition"] == expected


def test_pair_counts_never_exceed_either_marginal():
    """A pair cannot occur more often than the rarer of its two conditions."""
    from cym500.analysis.posture import config_findings

    f = config_findings()
    for pair, n in f["condition_pairs"].items():
        a, b = pair.split("+")
        assert n <= min(f["conditions"][a], f["conditions"][b]), pair


# --- private endpoints ------------------------------------------------------

def test_loopback_only_config_carries_no_private_endpoint_condition():
    # Records harvested under the earlier rule still list loopback URLs.
    from datetime import datetime, timezone

    from cym500.analysis.posture import _config_conditions
    from cym500.common.schema import ConfigArtefact, SourceLocation

    src = SourceLocation(kind="github", fetched_at=datetime.now(timezone.utc))

    def cfg(endpoints):
        return ConfigArtefact(id="c", raw_redacted={}, private_endpoints=endpoints, source=src)

    assert "private_endpoint" not in _config_conditions(cfg(["http://localhost:3000"]))
    assert "private_endpoint" in _config_conditions(cfg(["http://localhost:3000", "http://10.0.0.5"]))
