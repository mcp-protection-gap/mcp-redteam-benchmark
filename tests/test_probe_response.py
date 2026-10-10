"""The probe must match responses by id, skipping interleaved notifications."""
import os

# probe.py is the in-container entrypoint and reads its command at import.
os.environ.setdefault("INSTALL_COMMAND", "true")

from cym500.sandbox.probe import _await_response  # noqa: E402


def test_skips_notification_before_tools_list_response():
    msgs = iter([
        {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
        {"jsonrpc": "2.0", "id": "other", "method": "roots/list"},
        {"jsonrpc": "2.0", "id": "want", "result": {"tools": [{"name": "echo"}]}},
    ])
    out = _await_response(lambda: next(msgs), "want")
    assert out["result"]["tools"][0]["name"] == "echo"


def test_error_response_is_returned():
    msgs = iter([{"jsonrpc": "2.0", "id": "want", "error": {"code": -1}}])
    assert "error" in _await_response(lambda: next(msgs), "want")
