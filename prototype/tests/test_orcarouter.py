"""OrcaRouter Cyber Inference provider: API-key and OAuth 2.0 + PKCE entries, model catalog.

Every key/code/verifier here is fake. The network is either a local fake auth server or
a local upstream that records what the proxy sent.
"""

import base64
import hashlib
import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from veil import adopt, orcarouter
from veil.anthropic import Policy
from veil.detect import KnownValues
from veil.engine import Veil
from veil.proxy import LocalHTTPServer, make_handler
from veil.vault import Vault

FAKE_KEY = "sk-orca-test-0000-0000"
NEW_KEY = "sk-orca-test-1111-2222"
VERIFIER = "verifier-must-never-be-logged-0123456789"


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    """File-backed key store only (no real keychain) and a fresh $VEIL_HOME."""
    monkeypatch.setenv("VEIL_HOME", str(tmp_path / "home"))
    for var in ("ORCA_KEY", "ORCA_BASE_URL", "ORCA_AUTH_BASE_URL", "ORCA_API_BASE_URL",
                "VEIL_ORCAROUTER_API_KEY"):  # the opt-in live test reads ORCAROUTER_API_KEY
        monkeypatch.delenv(var, raising=False)
    yield tmp_path


@pytest.fixture
def veil():
    k = KnownValues()
    k.add("alice@acme-corp.com", "email", "c:2")
    k.add("Alice Wong", "name", "c:2")
    return Veil(Vault(":memory:", b"test-secret"), k)


# -- fake servers -------------------------------------------------------------------

class FakeAuth:
    """One origin, three paths: /auth (redirect or out-of-band), /api/v1/auth/keys."""

    def __init__(self, redirect="oob", scope="api", status=200, body=None, delay=0.0):
        self.calls, self.redirect, self.scope, self.status, self.body, self.delay = [], redirect, scope, status, body, delay
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                outer.calls.append(("GET", u.path, urllib.parse.parse_qs(u.query)))
                if u.path != "/auth":
                    self.send_response(404); self.end_headers(); return
                self.send_response(302)
                self.send_header("location", outer.redirect)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n)
                outer.calls.append(("POST", self.path, None, json.loads(raw or b"{}"),
                                    self.headers.get("authorization")))
                if outer.delay:
                    import time
                    time.sleep(outer.delay)
                payload = outer.body if outer.body is not None else {"key": NEW_KEY, "user_id": "u-9", "scope": outer.scope}
                data = json.dumps(payload).encode()
                self.send_response(outer.status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        try:
            self.srv.shutdown(); self.srv.server_close()
        except (OSError, ValueError):
            pass

    def exchanges(self):
        return [c for c in self.calls if c[0] == "POST"]


class Recording:
    captures = []
    status = 200
    reply = None

    @classmethod
    def reset(cls, status=200, reply=None):
        cls.captures, cls.status, cls.reply = [], status, reply

    @classmethod
    def handler(cls):
        outer = cls
        srv = HTTPServer(("127.0.0.1", 0), None)

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def finish(self):
                try:
                    super().finish()
                except (OSError, ValueError):
                    pass

            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n) if n else b""
                outer.captures.append({"method": self.command, "path": self.path,
                                       "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "body": json.loads(raw) if raw else None})
                data = json.dumps(outer.reply or {"choices": [{"message": {"role": "assistant",
                                                                           "content": "ok for alice@acme-corp.com"}}]},
                                  ensure_ascii=False).encode()
                self.send_response(outer.status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _do
            do_POST = _do

        srv.RequestHandlerClass = H
        cls.srv = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    @classmethod
    def base(cls):
        return f"http://127.0.0.1:{cls.srv.server_address[1]}"


def run_proxy(veil, upstream, credential):
    client = httpx.Client(trust_env=False)
    px = LocalHTTPServer(("127.0.0.1", 0), make_handler(
        veil, Policy(), upstream, client, log=open(os.devnull, "w"), openai_upstream=upstream,
        orcarouter_credential=credential))
    threading.Thread(target=px.serve_forever, daemon=True).start()
    return px, client, f"http://127.0.0.1:{px.server_port}"


def chat_request(body):
    return {"model": "orcarouter/auto", "messages": [{"role": "user", "content": body}]}


# -- credential seam ----------------------------------------------------------------

def test_api_key_adapter_saves_reads_clears_and_masks():
    cred = orcarouter.connect_api_key(FAKE_KEY)
    assert cred.source == "api-key" and cred.key == FAKE_KEY
    back = orcarouter.load_credential()
    assert back.key == FAKE_KEY and back.source == "api-key" and back.generation == cred.generation
    assert FAKE_KEY not in repr(back) and back.masked().endswith(FAKE_KEY[-4:]) and "…" in back.masked()
    info = orcarouter.describe(back)
    assert FAKE_KEY not in json.dumps(info) and info["configured"] is True
    assert orcarouter.clear_credential() is True
    assert orcarouter.load_credential() is None
    assert orcarouter.clear_credential() is False


def test_api_key_format_check_and_env_source(monkeypatch):
    with pytest.raises(orcarouter.OrcaError):
        orcarouter.connect_api_key("not-a-key")
    with pytest.raises(orcarouter.OrcaError):
        orcarouter.connect_api_key("sk-orca- two tokens")
    monkeypatch.setenv("ORCA_KEY", FAKE_KEY)
    got = orcarouter.load_credential()
    assert got.source == "env" and got.key == FAKE_KEY


def test_stored_credential_does_not_put_the_key_in_a_plain_side_file(isolate):
    orcarouter.connect_api_key(FAKE_KEY)
    wrapped = base64.b64encode(FAKE_KEY.encode())
    for root, _, files in os.walk(isolate / "home"):
        for f in files:
            data = open(os.path.join(root, f), "rb").read()
            if f == orcarouter.KEY_NAME:   # the store document: 0600, the key only as base64
                assert os.stat(os.path.join(root, f)).st_mode & 0o777 == 0o600
                assert FAKE_KEY.encode() not in data
                assert base64.b64encode(data) not in data  # base64 is not an encryption: documented, 0600
            else:
                assert FAKE_KEY.encode() not in data, f
                assert wrapped not in data, f


def test_pkce_helper_uses_crypto_rng_and_s256():
    a, b = orcarouter.new_pending("https://www.orcarouter.ai"), orcarouter.new_pending("https://www.orcarouter.ai")
    assert a.verifier != b.verifier and a.state != b.state
    assert len(a.verifier) == 43 and len(a.state) == 22
    assert a.challenge == base64.urlsafe_b64encode(hashlib.sha256(a.verifier.encode()).digest()).decode().rstrip("=")
    assert a.verifier not in a.url("http://127.0.0.1:1/cb")


def test_authorize_url_targets_auth_origin_only():
    p = orcarouter.new_pending("https://www.orcarouter.ai")
    u = urllib.parse.urlparse(p.url("oob"))
    q = urllib.parse.parse_qs(u.query)
    assert u.scheme == "https" and u.netloc == "www.orcarouter.ai" and u.path == "/auth"
    assert q["callback_url"] == ["oob"] and q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [p.challenge] and q["state"] == [p.state] and q["scope"] == ["api"]
    assert orcarouter.exchange_url("https://www.orcarouter.ai") == "https://www.orcarouter.ai/api/v1/auth/keys"


def test_exchange_path_body_and_persistence():
    auth = FakeAuth()
    try:
        seen = {}

        def read_code(prompt):
            seen["prompt"] = prompt
            return "the-code"

        cred = orcarouter.connect("b", read_code=read_code, open_browser=lambda u: True,
                                  env={"ORCA_AUTH_BASE_URL": auth.base})
        assert seen["prompt"].startswith("Code")
        (call,) = auth.exchanges()
        assert call[1] == "/api/v1/auth/keys" and call[2] is None
        assert call[3]["code"] == "the-code" and call[3]["code_challenge_method"] == "S256"
        assert call[3]["code_verifier"] != VERIFIER and len(call[3]["code_verifier"]) == 43
        assert call[4] is None  # no client secret / no auth header on exchange
        assert cred.source == "pkce" and cred.key == NEW_KEY and cred.scope == "api"
        stored = orcarouter.load_credential()
        assert stored.key == NEW_KEY and stored.account == "u-9"
    finally:
        auth.close()


def test_pkce_denial_scope_downgrade_429_and_network_failure_are_terminal():
    cases = [
        dict(status=403, body={"error": "access_denied"}),
        dict(status=429, body={"error": "rate_limited"}),
        dict(status=200, body={"key": NEW_KEY, "scope": "connector"}),
        dict(status=200, body={"user_id": "x"}),
    ]
    for case in cases:
        auth = FakeAuth(**case)
        try:
            pending = orcarouter.new_pending(auth.base)
            with pytest.raises(orcarouter.OrcaError):
                orcarouter.exchange(pending, "c", httpx.Client(trust_env=False))
        finally:
            auth.close()
    pending = orcarouter.new_pending("http://127.0.0.1:9")
    with pytest.raises(orcarouter.OrcaError):
        orcarouter.exchange(pending, "c", httpx.Client(trust_env=False, timeout=2))
    assert orcarouter.load_credential() is None  # nothing half-written


def test_pkce_code_reuse_is_a_403_terminal():
    auth = FakeAuth(status=403, body={"error_code": "invalid_grant"})
    try:
        pending = orcarouter.new_pending(auth.base)
        for _ in range(2):
            with pytest.raises(orcarouter.OrcaError) as e:
                orcarouter.exchange(pending, "used", httpx.Client(trust_env=False))
            assert "start Connect again" in str(e.value)
    finally:
        auth.close()


def _drive_browser(monkeypatch, query_fn):
    """Act as the browser: hit the loopback callback_url named in the authorize URL."""
    import urllib.request

    def open_url(url: str) -> bool:
        holder["url"] = url
        cb = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["callback_url"][0]
        threading.Thread(target=lambda: urllib.request.urlopen(f"{cb}?" + query_fn(), timeout=10).read(),
                         daemon=True).start()
        return True
    holder = {"open": open_url, "url": None}
    return holder


def test_flow_a_state_mismatch_and_denial(monkeypatch):
    for query, needle in (("state=wrong&code=x", "state mismatch"),
                          ("state={s}&error=access_denied", "not approved")):
        p = orcarouter.new_pending("https://www.orcarouter.ai")
        holder = _drive_browser(monkeypatch, lambda q=query: q.format(s=p.state))
        with pytest.raises(orcarouter.OrcaError) as e:
            orcarouter.flow_a(p, open_browser=lambda u: holder["open"](u), timeout=5, print_fn=lambda s: None)
        assert needle in str(e.value)


def test_flow_a_happy_path_exchanges_code(monkeypatch):
    auth = FakeAuth()
    try:
        p = orcarouter.new_pending(auth.base)
        holder = _drive_browser(monkeypatch, lambda: f"state={p.state}&code=abc")
        cred = orcarouter.connect("a", open_browser=lambda u: holder["open"](u), print_fn=lambda s: None,
                                  env={"ORCA_AUTH_BASE_URL": auth.base}, pending=p)
        (call,) = auth.exchanges()
        assert call[3]["code"] == "abc" and call[3]["code_verifier"] == p.verifier
        assert cred.key == NEW_KEY and orcarouter.load_credential().key == NEW_KEY
    finally:
        auth.close()


def test_flow_a_prints_authorize_url_with_callback(monkeypatch):
    printed = []
    auth = FakeAuth()
    try:
        p = orcarouter.new_pending(auth.base)
        holder = _drive_browser(monkeypatch, lambda: f"state={p.state}&code=abc")
        orcarouter.connect("a", open_browser=lambda u: holder["open"](u), print_fn=printed.append,
                           env={"ORCA_AUTH_BASE_URL": auth.base}, pending=p)
        # the browser hook received the real authorize URL (port bound before the browser opens)
        opened = holder["url"]
        q = urllib.parse.parse_qs(urllib.parse.urlparse(opened).query)
        cb = q["callback_url"][0]
        assert cb.startswith("http://127.0.0.1:") and cb.endswith("/cb")
        assert int(urllib.parse.urlparse(cb).port) > 0
        assert q["state"] == [p.state] and q["code_challenge"] == [p.challenge]
        text = "\n".join(printed)
        assert "OrcaRouter" in text and text.rstrip().endswith(opened.split("?")[0] + "?" + urllib.parse.urlparse(opened).query)
    finally:
        auth.close()


def test_flow_a_timeout_is_terminal_not_a_hang():
    pending = orcarouter.new_pending("https://www.orcarouter.ai")
    with pytest.raises(orcarouter.OrcaError) as e:
        orcarouter.flow_a(pending, open_browser=lambda u: True, timeout=0.3, print_fn=lambda s: None)
    assert "timed out" in str(e.value)


def test_both_adapters_yield_the_same_credential_shape_and_downstream_ignores_source():
    key_cred = orcarouter.connect_api_key(FAKE_KEY)
    auth = FakeAuth()
    try:
        pkce_cred = orcarouter.connect("b", read_code=lambda _: "c", open_browser=lambda u: True,
                                       env={"ORCA_AUTH_BASE_URL": auth.base})
    finally:
        auth.close()
    assert type(pkce_cred) is type(key_cred)
    for cred in (key_cred, pkce_cred):
        Recording.reset()
        Recording.handler()
        px, client, base = run_proxy(_veil(), Recording.base(), lambda c=cred: c)
        try:
            assert client.post(base + "/v1/chat/completions", json=chat_request("hi")).status_code == 200
            assert Recording.captures[-1]["headers"]["authorization"] == f"Bearer {cred.key}"
            orcarouter.discover(client, cred, env={"ORCA_API_BASE_URL": Recording.base()})
            assert Recording.captures[-1]["path"] == "/models"
            assert Recording.captures[-1]["headers"]["authorization"] == f"Bearer {cred.key}"
        finally:
            px.shutdown(); Recording.srv.shutdown(); client.close()


def test_origins_are_separate_and_overridable(monkeypatch):
    assert orcarouter.auth_base({}) == "https://www.orcarouter.ai"
    assert orcarouter.api_base({}) == "https://api.orcarouter.ai/v1"
    assert orcarouter.auth_base({"ORCA_BASE_URL": "https://orca.internal"}) == "https://orca.internal"
    assert orcarouter.api_base({"ORCA_BASE_URL": "https://orca.internal"}) == "https://orca.internal/v1"
    assert orcarouter.auth_base({"ORCA_BASE_URL": "https://a.internal", "ORCA_AUTH_BASE_URL": "https://b.internal"}) \
        == "https://b.internal"
    assert orcarouter.api_base({"ORCA_BASE_URL": "https://a.internal", "ORCA_API_BASE_URL": "https://c.internal/v1"}) \
        == "https://c.internal/v1"
    assert orcarouter.api_base({"ORCA_API_BASE_URL": "http://127.0.0.1:9000/v1"}) == "http://127.0.0.1:9000/v1"
    with pytest.raises(orcarouter.OrcaError):
        orcarouter.auth_base({"ORCA_AUTH_BASE_URL": "http://www.orcarouter.ai"})
    ex = urllib.parse.urlparse(orcarouter.exchange_url(orcarouter.auth_base({})))
    assert (ex.netloc, ex.path) == ("www.orcarouter.ai", "/api/v1/auth/keys")
    assert not orcarouter.exchange_url(orcarouter.auth_base({})).startswith("https://api.orcarouter.ai")


def test_reauth_marks_only_the_rejected_generation_without_refresh():
    old = orcarouter.connect_api_key(FAKE_KEY)
    new = orcarouter.connect_api_key(NEW_KEY)  # reconnect
    late = orcarouter.mark_reauth(old)          # a late 401 from the old generation
    assert late.key == NEW_KEY and late.needs_reauth is False
    cur = orcarouter.mark_reauth(new)
    assert cur.needs_reauth is True and orcarouter.requires_login(cur)
    assert orcarouter.load_credential().key == NEW_KEY  # not silently deleted
    assert orcarouter.connect_api_key(NEW_KEY).needs_reauth is False   # a new login clears it
    src = open(orcarouter.__file__).read()
    assert "refresh_token" not in src and "grant_type=refresh" not in src


def test_verifier_and_key_never_reach_logs(isolate, capsys):
    auth = FakeAuth()
    try:
        printed = []
        pending_holder = {}
        orig = orcarouter.new_pending

        def spy(*a, **k):
            p = orig(*a, **k)
            pending_holder["p"] = p
            return p

        orcarouter.new_pending = spy
        try:
            orcarouter.connect("b", read_code=lambda _: "c", open_browser=lambda u: True,
                               env={"ORCA_AUTH_BASE_URL": auth.base}, print_fn=printed.append)
        finally:
            orcarouter.new_pending = orig
    finally:
        auth.close()
    out = capsys.readouterr()
    text = "\n".join(printed) + out.out + out.err
    assert pending_holder["p"].verifier not in text
    assert NEW_KEY not in text
    assert pending_holder["p"].challenge in text  # the URL is printed for manual opening


# -- model catalog + capability filters --------------------------------------------

CATALOG = {"data": [
    {"id": "orcarouter/auto", "name": "Auto", "context_length": 200000,
     "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}},
    {"id": "anthropic/claude-opus-4.8", "name": "Opus", "context_length": 200000,
     "supported_endpoint_types": ["anthropic"], "architecture": {"input_modalities": ["text", "image"]}},
    {"id": "openai/gpt-5.5", "name": "GPT-5.5", "context_length": 400000,
     "supported_endpoint_types": ["openai", "openai-response"],
     "architecture": {"input_modalities": ["text", "image"]},
     "reasoning": {"efforts": ["low", "medium", "high", "xhigh"]}},
    {"id": "microsoft/text-embedding-v3", "name": "Embed", "supported_endpoint_types": ["embeddings"],
     "architecture": {"input_modalities": ["text"]}},
    {"id": "google/imagen-4", "name": "Imagen", "supported_endpoint_types": ["image-generation"],
     "architecture": {"output_modalities": ["image"]}},
    {"id": "videococ/v-1", "name": "Video", "supported_endpoint_types": ["openai-video"]},
    {"id": "jina/rerank-v3", "name": "Rerank", "supported_endpoint_types": ["jina-rerank"]},
    {"id": "nocap/unknown", "name": "Unknown", "architecture": {}},
    {"id": "bogus-id", "name": "No namespace"},
]}


def test_catalog_parsing_and_capability_filters():
    models = orcarouter.parse_catalog(CATALOG)
    ids = [m["id"] for m in models]
    assert "bogus-id" not in ids
    chat = [m["id"] for m in orcarouter.filter_capability(models, "chat")]
    assert chat == ["orcarouter/auto", "anthropic/claude-opus-4.8", "openai/gpt-5.5"]  # never embed/image/video/rerank
    mm = [m["id"] for m in orcarouter.filter_capability(models, "multimodal", {"image"})]
    assert mm == ["anthropic/claude-opus-4.8", "openai/gpt-5.5"]  # no declared image input -> fail closed
    assert [m["id"] for m in orcarouter.filter_capability(models, "embedding")] == ["microsoft/text-embedding-v3"]
    assert [m["id"] for m in orcarouter.filter_capability(models, "image")] == ["google/imagen-4"]
    assert [m["id"] for m in orcarouter.filter_capability(models, "video")] == ["videococ/v-1"]
    assert [m["id"] for m in orcarouter.filter_capability(models, "rerank")] == ["jina/rerank-v3"]
    assert orcarouter.reasoning_efforts(models, "openai/gpt-5.5") == ["low", "medium", "high", "xhigh"]


def test_full_catalog_shape_with_openrouter_fields():
    payload = {"data": [{"id": "openai/gpt-5.5", "name": "GPT-5.5", "supported_endpoint_types": ["openai"],
                         "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]}}]}
    models = orcarouter.parse_catalog(payload)
    assert models[0]["input_modalities"] == ["image", "text"]


def test_selector_clears_incompatible_retained_value():
    models = orcarouter.parse_catalog(CATALOG)
    opts = orcarouter.selector_options(models, "chat", selected="orcarouter/auto")
    assert opts["selected"] == "orcarouter/auto" and not opts["cleared"]
    opts = orcarouter.selector_options(models, "multimodal", selected="orcarouter/auto", modalities={"image"})
    assert opts["selected"] is None and opts["cleared"] and "orcarouter/auto" not in opts["models"]


def test_discovery_is_live_and_authoritative_then_falls_back_to_verified_seed():
    Recording.reset(reply=CATALOG)
    up = Recording.handler()
    try:
        cred = orcarouter.Credential(key=FAKE_KEY, source="api-key")
        models, live, note = orcarouter.discover(httpx.Client(trust_env=False), cred, env={"ORCA_API_BASE_URL": Recording.base()})
        assert live and len(models) == 8 and "8 models" in note
        first = Recording.captures[0]
        assert first["path"] == "/models" and first["headers"]["authorization"] == f"Bearer {FAKE_KEY}"
        Recording.reset(status=500, reply={})
        models, live, note = orcarouter.discover(httpx.Client(trust_env=False), cred, env={"ORCA_API_BASE_URL": Recording.base()})
        assert not live and "fallback" in note
        assert [m["id"] for m in models] == [m["id"] for m in orcarouter.SEED_CATALOG]
        assert orcarouter.reasoning_efforts(models, "openai/gpt-5.5") == ["low", "medium", "high", "xhigh"]
        Recording.reset(status=401, reply={})
        models, live, note = orcarouter.discover(httpx.Client(trust_env=False), cred, env={"ORCA_API_BASE_URL": Recording.base()})
        assert models == [] and not live and "reconnect" in note
    finally:
        up.shutdown()
    models, live, note = orcarouter.discover(httpx.Client(trust_env=False), cred,
                                             env={"ORCA_API_BASE_URL": "http://127.0.0.1:9"})
    assert not live and models == [dict(m) for m in orcarouter.SEED_CATALOG]


def test_seed_has_brand_default_and_no_free_text_namespace_gaps():
    ids = [m["id"] for m in orcarouter.SEED_CATALOG]
    assert orcarouter.DEFAULT_MODEL == "orcarouter/auto" and ids[0] == "orcarouter/auto"
    assert "orcarouter/fusion" in ids
    assert all("/" in i for i in ids)


# -- proxy integration: real request path through the implemented provider ----------

def _veil():
    k = KnownValues()
    k.add("alice@acme-corp.com", "email", "c:2"); k.add("Alice Wong", "name", "c:2")
    return Veil(Vault(":memory:", b"s"), k)


def test_proxy_uses_orcarouter_key_redacts_and_rehydrates():
    Recording.reset()
    up = Recording.handler()
    cred = orcarouter.connect_api_key(FAKE_KEY)  # the api-key adapter feeds the proxy
    px, client, base = run_proxy(_veil(), Recording.base(), lambda: orcarouter.load_credential())
    try:
        r = client.post(base + "/v1/chat/completions", json=chat_request("why was alice@acme-corp.com billed twice?"),
                        headers={"authorization": "Bearer client-junk"})
        assert r.status_code == 200, r.text
        sent = Recording.captures[-1]
        assert sent["path"] == "/v1/chat/completions"
        assert sent["headers"]["authorization"] == f"Bearer {FAKE_KEY}"   # client credential replaced
        assert "alice@acme-corp.com" not in json.dumps(sent["body"])
        assert "alice@acme-corp.com" in r.json()["choices"][0]["message"]["content"]  # rehydrated locally
        h = client.get(base + "/veil/health").json()
        assert h["provider"] == "orcarouter" and h["orcarouter"]["configured"] is True
        assert FAKE_KEY not in json.dumps(h)
    finally:
        px.shutdown(); up.shutdown(); client.close()


def test_proxy_anthropic_format_also_routes_to_orcarouter():
    Recording.reset(reply={"id": "m", "type": "message", "role": "assistant", "model": "orcarouter/auto",
                           "content": [{"type": "text", "text": "hello alice@acme-corp.com"}],
                           "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}})
    up = Recording.handler()
    orcarouter.connect_api_key(FAKE_KEY)
    px, client, base = run_proxy(_veil(), Recording.base(), lambda: orcarouter.load_credential())
    try:
        r = client.post(base + "/v1/messages", json={"model": "orcarouter/auto", "max_tokens": 5,
                                                     "messages": [{"role": "user", "content": "alice@acme-corp.com"}]})
        assert r.status_code == 200, r.text
        assert Recording.captures[-1]["path"] == "/v1/messages"
        assert Recording.captures[-1]["headers"]["authorization"] == f"Bearer {FAKE_KEY}"
        assert "alice@acme-corp.com" in r.json()["content"][0]["text"]
    finally:
        px.shutdown(); up.shutdown(); client.close()


def test_proxy_401_marks_the_exact_generation_for_reauth():
    Recording.reset(status=401, reply={"error": "revoked"})
    Recording.handler()
    old = orcarouter.connect_api_key(FAKE_KEY)
    cur = {"cred": old}
    px, client, base = run_proxy(_veil(), Recording.base(), lambda: cur["cred"])
    try:
        cur["cred"] = orcarouter.connect_api_key(NEW_KEY)       # the user reconnects ...
        late = orcarouter.mark_reauth(old)                       # ... a request captured before it ends with 401
        assert late.key == NEW_KEY and late.needs_reauth is False
        cur["cred"] = orcarouter.load_credential()
        r = client.post(base + "/v1/chat/completions", json=chat_request("hi"))
        assert r.status_code == 401
        stored = orcarouter.load_credential()
        assert stored.key == NEW_KEY and stored.needs_reauth and orcarouter.requires_login(stored)
        assert not hasattr(orcarouter, "refresh")  # a durable key: no refresh grant, no retry loop
    finally:
        px.shutdown(); Recording.srv.shutdown(); client.close()


def test_adopt_settings_for_orcarouter_provider(isolate):
    from veil import state
    state.save_config({"provider": "orcarouter", "model": "orcarouter/auto"})
    path = adopt.write_claude_settings(str(isolate / "proj"), 8787, hooks=False)
    env = json.load(open(path))["env"]
    assert env["ANTHROPIC_AUTH_TOKEN"] == "veil-local"
    assert env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == "orcarouter/auto"
    assert FAKE_KEY not in json.dumps(env)
    state.save_config({})
    path = adopt.write_claude_settings(str(isolate / "proj2"), 8787, hooks=False)
    assert "ANTHROPIC_AUTH_TOKEN" not in json.load(open(path))["env"]


def test_proxy_cli_forwards_the_explicit_root_not_v1(monkeypatch):
    """The proxy appends /v1/chat/completions to the upstream, so the CLI must pass https://api.orcarouter.ai
    (passing api_base() put requests at /v1/v1/chat/completions on the live gateway)."""
    import veil.cli as cli
    import veil.proxy as proxy
    import veil.reseed as reseed_mod
    import veil.state as state_mod
    from veil import orcarouter

    class Stop(Exception):
        pass

    seen = {}

    def fake_serve(veil, policy, port, upstream, *args, **kw):
        seen.update(upstream=upstream, args=args, kw=kw, port=port)
        raise Stop

    stub = type("V", (), {"known": (), "vault": type("C", (), {"cipher": None})(), "reseed": False,
                          "redact": lambda self, t, **k: t, "rehydrate": lambda self, t: t})()
    monkeypatch.setattr(cli, "_provider_auth", lambda args: orcarouter.connect_api_key(FAKE_KEY))
    monkeypatch.setattr(proxy, "serve", fake_serve)
    monkeypatch.setattr(reseed_mod, "warm", lambda known: None, raising=False)
    monkeypatch.setattr(state_mod, "load", lambda: stub)
    with pytest.raises(Stop):
        cli.main(["proxy", "--provider", "orcarouter", "--port", "0", "--reseed-interval", "0"])
    assert seen["port"] == 0
    assert seen["upstream"] == "https://api.orcarouter.ai"
    # openai_upstream is passed positionally right after capture
    assert [a for a in seen["args"][:6] if isinstance(a, str)] == ["https://api.orcarouter.ai"]
    assert seen["kw"]["orcarouter_credential"]().key == FAKE_KEY


def test_pkce_connect_accepts_a_caller_built_pending(monkeypatch):
    """A UI that renders the authorize URL first passes its Pending: the verifier and state must survive."""
    auth = FakeAuth()
    try:
        p = orcarouter.new_pending(auth.base)
        holder = _drive_browser(monkeypatch, lambda: f"state={p.state}&code=zzz")
        cred = orcarouter.connect("a", open_browser=lambda u: holder["open"](u), print_fn=lambda s: None,
                                  env={"ORCA_AUTH_BASE_URL": auth.base}, pending=p)
        (call,) = auth.exchanges()
        assert call[3]["code"] == "zzz" and call[3]["code_verifier"] == p.verifier
        assert cred.key == NEW_KEY
    finally:
        auth.close()


def test_connect_api_key_without_argument_uses_env_and_never_echoes_it(monkeypatch):
    monkeypatch.setenv(orcarouter.KEY_ENV, FAKE_KEY)
    assert orcarouter.uses_env_key()
    cred = orcarouter.connect_api_key(FAKE_KEY)
    assert FAKE_KEY not in repr(cred) and FAKE_KEY not in json.dumps(orcarouter.describe(cred))


import os, threading
import httpx

from veil import orcarouter, state
from veil.anthropic import Policy
from veil.proxy import LocalHTTPServer, make_handler


def test_live_orcarouter_gateway_end_to_end(monkeypatch, isolate):
    """Opt-in live check through the implemented provider. Runs only with ORCAROUTER_API_KEY in
    the environment (the independent verification grants it to this test alone)."""
    key = os.environ.get("ORCAROUTER_API_KEY")
    if not key:
        pytest.skip("ORCAROUTER_API_KEY is not set")
    cred = orcarouter.connect_api_key(key)
    base = orcarouter.api_base()
    assert base == "https://api.orcarouter.ai/v1"

    client = httpx.Client(timeout=60, trust_env=False)
    models, live, note = orcarouter.discover(client, cred)
    assert live, note
    chat = orcarouter.selector_options(models, "chat", live=True)["options"]
    assert chat, note  # the text selector is built from GET https://api.orcarouter.ai/v1/models
    assert "orca/orcacyber-zero-1.5" in [m["id"] for m in chat]  # a cyber-tier model for security work

    # inference through the proxy handler: a placeholder client credential is replaced by the stored one
    veil = state.load()
    root = base[:-3]
    srv = LocalHTTPServer(("127.0.0.1", 0), make_handler(veil, Policy(), root, client, openai_upstream=root,
                                                         orcarouter_credential=lambda: orcarouter.load_credential()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        c = httpx.Client(timeout=120, trust_env=False)
        model = "deepseek/deepseek-v4.1-flash"
        r1 = c.post(f"http://127.0.0.1:{port}/v1/chat/completions", headers={"authorization": "Bearer placeholder"},
                    json={"model": model, "max_tokens": 16,
                          "messages": [{"role": "user", "content": "Reply OK"}]})
        assert r1.status_code == 200, r1.text[:300]
        assert r1.json()["choices"]
        r2 = c.post(f"http://127.0.0.1:{port}/v1/messages",
                    headers={"authorization": "Bearer placeholder", "anthropic-version": "2023-06-01"},
                    json={"model": model, "max_tokens": 16,
                          "messages": [{"role": "user", "content": "Reply OK"}]})
        assert r2.status_code == 200, r2.text[:300]
        assert r2.json()["type"] == "message"
    finally:
        srv.shutdown()
        srv.server_close()
