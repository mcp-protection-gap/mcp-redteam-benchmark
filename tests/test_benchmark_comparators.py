"""Attribution parsing for the Agent Scan comparator.

Agent Scan reports issues at server granularity and changed how it names the
offending tool between the first benchmark run and re-execution. Both forms are
pinned here, because a silent parse failure does not raise: it reports every
tool as clean, which shows up as a true-positive rate of zero rather than as an
error.
"""
import json

from cym500.benchmark.comparators.mcp_scan import _parse_flagged_tools

SERVED = ["tAAA", "tBBB", "tCCC"]


def _out(issue: dict) -> str:
    return json.dumps({"/cfg.json": {"servers": [{"signature": {"tools": []}}], "issues": [issue]}})


def test_attribution_by_affected_tool_indices():
    """Current schema: extra_data.affected_tools indexes the served order."""
    out = _out({"code": "W001", "extra_data": {"affected_tools": [0, 2]}})
    assert _parse_flagged_tools(out, SERVED) == {"tAAA": ["W001"], "tCCC": ["W001"]}


def test_attribution_by_tool_name_in_evidence():
    """Legacy schema: the offending tool is named in the issue text."""
    out = _out({"code": "E001", "extra_data": {"evidence": "The tBBB tool's description ..."}})
    assert _parse_flagged_tools(out, SERVED) == {"tBBB": ["E001"]}


def test_indices_take_precedence_and_ignore_out_of_range():
    out = _out({"code": "W015", "extra_data": {"affected_tools": [1, 99]}})
    assert _parse_flagged_tools(out, SERVED) == {"tBBB": ["W015"]}


def test_no_issues_means_nothing_flagged():
    assert _parse_flagged_tools(json.dumps({"/cfg.json": {"issues": []}}), SERVED) == {}


def test_unparseable_output_is_not_silently_clean():
    """Malformed output returns empty, so callers must not treat it as a scan."""
    assert _parse_flagged_tools("not json", SERVED) == {}


def test_scan_failure_detects_rate_limit():
    """A 429 'daily usage limit' is reported inside exit-0 JSON; it must be caught."""
    from cym500.benchmark.comparators.mcp_scan import _scan_failure

    out = json.dumps({"/cfg.json": {"issues": [], "error": None, "servers": [
        {"name": "target", "error": {"message": "Daily usage limit reached", "is_failure": True}}
    ]}})
    assert _scan_failure(out) == "Daily usage limit reached"
    assert _scan_failure("not json")
    assert _scan_failure(json.dumps({"/cfg.json": {"issues": [], "error": None,
                                                   "servers": [{"name": "t", "error": None}]}})) is None
