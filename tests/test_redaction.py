from cym500.common.redaction import (
    find_private_endpoints,
    redact_dict,
    redact_text,
    scan_text,
)


def test_detects_github_pat():
    text = "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    hits = scan_text(text)
    assert any(h.kind == "github_pat" for h in hits)


def test_redact_replaces_value():
    text = "key=sk-abcdefghijklmnopqrstuvwx"
    hits = scan_text(text)
    out = redact_text(text, hits)
    assert "sk-abcdefghijklmnopqrstuvwx" not in out
    assert "<REDACTED:" in out


def test_redact_dict_walks_nested():
    obj = {"server": {"env": {"OPENAI_API_KEY": "sk-AAAAAAAAAAAAAAAAAAAA"}}}
    redacted, hits = redact_dict(obj)
    assert hits
    assert "sk-AAAAAAAAAAAAAAAAAAAA" not in str(redacted)


def test_finds_private_endpoint():
    text = "url=http://10.0.0.5:8080/mcp"
    out = find_private_endpoints(text)
    assert out


def test_loopback_is_not_a_private_endpoint():
    # Loopback discloses no network topology; counting it once inflated the
    # private-endpoint condition from 13 configurations to 151.
    from cym500.common.redaction import is_loopback, non_loopback

    assert find_private_endpoints("url=http://localhost:3000/mcp") == []
    assert is_loopback("http://localhost") and is_loopback("https://LOCALHOST:8001")
    assert is_loopback("http://127.0.0.1:8080")
    assert not is_loopback("http://localhost.corp") and not is_loopback("http://10.0.0.5")
    assert non_loopback(["http://localhost:3000", "http://10.0.0.5"]) == ["http://10.0.0.5"]


def test_placeholders_are_recognised_but_real_shapes_are_not():
    from cym500.common.redaction import is_placeholder

    assert is_placeholder("slack_token", "xoxb-your-bot-token-here")
    assert is_placeholder("slack_token", "xoxp-your-user-token-optional")
    assert is_placeholder("github_pat", "ghp_" + "X" * 36)
    # Slack without numeric segments cannot be a real token.
    assert is_placeholder("slack_token", "xoxb-abcdefghijklmnop")
    # Synthetic real-shaped values (not real credentials) are not placeholders.
    assert not is_placeholder("slack_token", "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx")
    assert not is_placeholder("github_pat", "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6")


def test_placeholder_is_still_redacted():
    text = '{"SLACK_BOT_TOKEN": "xoxb-your-bot-token-here"}'
    hits = scan_text(text)
    assert hits and "xoxb-your" not in redact_text(text, hits)
