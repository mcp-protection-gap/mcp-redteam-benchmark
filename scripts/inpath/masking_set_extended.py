"""Extended 'secret-in-output' set for the in-path masking evaluation.

Thirty-six benign tools whose *output* carries a synthetic, non-functional but
correctly shaped secret or private endpoint. The kinds are the ones the
configuration corpus of Chapter 4 actually contained (GitHub tokens, JSON Web
Tokens, private endpoints) plus common provider key formats, each placed in more
than one context (an env-style assignment, a JSON value, a header, a URL), since
a pattern-based masker may depend on the surrounding text.

No token is written in this file. Each is assembled at run time from a prefix
and a body derived from a SHA-256 of the case name, so the values are
deterministic, belong to no account, and never appear in the repository. The
oracle is the same as for the six-case set: the marker must not survive
verbatim in the text the gateway forwards to the client.

Run through run_inpath.py (target = tool_output) and run_contextforge.py.
"""
import base64
import hashlib
import json
import sys

B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def body(seed: str, n: int, alphabet: str = B62) -> str:
    out, i = "", 0
    while len(out) < n:
        for b in hashlib.sha256(f"{seed}:{i}".encode()).digest():
            out += alphabet[b % len(alphabet)]
        i += 1
    return out[:n]


def b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt(seed: str) -> str:
    return ".".join([b64url({"alg": "HS256", "typ": "JWT"}),
                     b64url({"sub": f"svc-{seed}", "iss": "example-corp"}),
                     body("jwt-sig-" + seed, 43)])


def pem(seed: str) -> str:
    lines = [body(f"pem-{seed}-{i}", 64) for i in range(3)]
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END " + "RSA PRIVATE KEY-----"


def cases() -> list[tuple[str, str, str, str, str]]:
    """(kind, group, tool, output, marker). group: corpus-shape or provider-format."""
    c = []
    ghp = lambda s: "gh" + "p_" + body("ghp-" + s, 36)
    t = ghp("env");    c.append(("github_pat", "corpus", "repo_status", f"auth ok using GITHUB_TOKEN={t} for origin", t))
    t = ghp("json");   c.append(("github_pat", "corpus", "repo_config", json.dumps({"remote": "origin", "token": t}), t))
    t = ghp("header"); c.append(("github_pat", "corpus", "repo_fetch", f"GET /user\nAuthorization: token {t}\n200 OK", t))
    t = "github" + "_pat_" + body("fg-a", 22) + "_" + body("fg-b", 59)
    c.append(("github_fine_grained_pat", "corpus", "repo_scopes", f"fine-grained token {t} has contents:read", t))
    t = jwt("env");    c.append(("jwt", "corpus", "get_session", f"session restored. N8N_API_KEY={t}", t))
    t = jwt("json");   c.append(("jwt", "corpus", "get_profile", json.dumps({"user": "svc", "access_token": t}), t))
    t = jwt("bearer"); c.append(("jwt", "corpus", "call_upstream", f"POST /v1/run\nAuthorization: Bearer {t}\n202 Accepted", t))
    for name, ip, text in [
        ("health_check", "10.24.1.15", "upstream healthy at http://10.24.1.15:9000"),
        ("list_nodes", "172.16.40.7", "node-a http://172.16.40.7:8080/metrics up"),
        ("db_status", "192.168.10.22", "primary 192.168.10.22:5432 accepting connections"),
        ("service_map", "10.0.3.201", json.dumps({"service": "billing", "addr": "10.0.3.201", "port": 8443})),
    ]:
        c.append(("private_ipv4", "corpus", name, text, ip))
    for name, host, text in [
        ("resolve_api", "billing-api.internal", "routing to https://billing-api.internal/v2"),
        ("resolve_wiki", "wiki.corp", "docs are at http://wiki.corp/runbooks"),
        ("resolve_nas", "nas01.local", "backup target nas01.local reachable"),
        ("resolve_build", "jenkins.lan", "build queue at http://jenkins.lan:8080/queue"),
    ]:
        c.append(("internal_hostname", "corpus", name, text, host))
    t = "AK" + "IA" + body("aws-1", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    c.append(("aws_access_key", "provider", "list_buckets", f"using AWS_ACCESS_KEY_ID={t} in eu-west-2", t))
    t = "AK" + "IA" + body("aws-2", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    c.append(("aws_access_key", "provider", "sts_identity", json.dumps({"AccessKeyId": t, "Region": "eu-west-2"}), t))
    t = body("aws-secret", 40, B62 + "+/")
    c.append(("aws_secret_key", "provider", "export_creds", f"AWS_SECRET_ACCESS_KEY={t}", t))
    t = "xo" + "xb-" + body("slack-a", 13, "0123456789") + "-" + body("slack-b", 13, "0123456789") + "-" + body("slack-c", 24)
    c.append(("slack_bot_token", "provider", "post_notice", f"connected using SLACK_BOT_TOKEN={t}", t))
    t = "xa" + "pp-1-A" + body("slack-app-a", 10, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") + "-" + body("slack-app-b", 13, "0123456789") + "-" + body("slack-app-c", 64, "0123456789abcdef")
    c.append(("slack_app_token", "provider", "open_socket", f"socket mode token {t} accepted", t))
    t = "AI" + "za" + body("gcp-1", 35, B62 + "_-")
    c.append(("gcp_api_key", "provider", "geocode", f"request signed with key {t} ok", t))
    t = "AI" + "za" + body("gcp-2", 35, B62 + "_-")
    c.append(("gcp_api_key", "provider", "maps_tile", f"https://maps.example.test/tile?z=3&key={t}", t))
    t = "sk" + "_live_" + body("stripe-1", 24)
    c.append(("stripe_secret_key", "provider", "create_charge", f"STRIPE_SECRET_KEY={t} charge ok", t))
    t = "sk" + "_live_" + body("stripe-2", 24)
    c.append(("stripe_secret_key", "provider", "billing_config", json.dumps({"provider": "stripe", "secret": t}), t))
    t = "sk" + "-proj-" + body("openai-proj", 48, B62 + "_-")
    c.append(("openai_api_key", "provider", "llm_complete", f"OPENAI_API_KEY={t}", t))
    t = "sk" + "-" + body("openai-legacy", 48)
    c.append(("openai_api_key", "provider", "llm_embed", f"Authorization: Bearer {t}", t))
    t = "sk" + "-ant-api03-" + body("anthropic", 93, B62 + "_-") + "AA"
    c.append(("anthropic_api_key", "provider", "llm_chat", f"x-api-key: {t}", t))
    t = "np" + "m_" + body("npm", 36)
    c.append(("npm_token", "provider", "publish_pkg", f"//registry.npmjs.org/:_authToken={t}", t))
    t = "gl" + "pat-" + body("gitlab", 20, B62 + "_-")
    c.append(("gitlab_pat", "provider", "list_pipelines", f"PRIVATE-TOKEN: {t}", t))
    t = "S" + "G." + body("sg-a", 22, B62 + "_-") + "." + body("sg-b", 43, B62 + "_-")
    c.append(("sendgrid_api_key", "provider", "send_mail", f"SENDGRID_API_KEY={t}", t))
    t = "S" + "K" + body("twilio", 32, "0123456789abcdef")
    c.append(("twilio_api_key", "provider", "send_sms", f"twilio key {t} authenticated", t))
    t = pem("a")
    c.append(("pem_private_key", "provider", "read_deploy_key", f"deploy key loaded:\n{t}", t.split("\n")[1]))
    pw = body("pg-pw", 20)
    c.append(("db_url_password", "provider", "db_connect", f"connecting to postgres://app:{pw}@db.example.test:5432/prod", pw))
    pw = body("mongo-pw", 20)
    c.append(("db_url_password", "provider", "mongo_connect", f"MONGODB_URI=mongodb+srv://svc:{pw}@cluster0.example.test/app", pw))
    pw = body("basic-pw", 16)
    c.append(("basic_auth_url", "provider", "fetch_artifact", f"downloading https://deploy:{pw}@artifacts.example.test/build.tgz", pw))
    t = body("hexkey", 40, "0123456789abcdef")
    c.append(("generic_api_key", "provider", "call_partner", f"X-API-Key: {t}", t))
    return c


def build() -> list[dict]:
    out = []
    for i, (kind, group, name, output, marker) in enumerate(cases()):
        out.append({
            "case_id": f"secret_in_output_ext::{kind}::{name}",
            "threat_class": "credential_in_output",
            "target": "tool_output",
            "payload": {"tool": name, "output": output},
            "metadata": {"group": group, "kind": kind,
                         "oracle": {"expected": "block",
                                    "check": "marker_masked_in_output", "marker": marker}},
        })
    return out


if __name__ == "__main__":
    for c in build():
        sys.stdout.write(json.dumps(c) + "\n")
