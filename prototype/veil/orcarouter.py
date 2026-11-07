"""OrcaRouter Cyber Inference: a named provider preset for this local proxy.

OrcaRouter (https://www.orcarouter.ai) is an OpenAI-compatible AI gateway: many
models behind one endpoint (https://api.orcarouter.ai/v1). The "Cyber Inference"
entry is the provider as this proxy offers it to security teams doing authorized
work -- red-team reasoning on the dedicated OrcaCyber models, blue-team gateway
controls on the same endpoint. veil stays the privacy layer in front of it: the
gateway sees pseudonyms, never real people.

    veil proxy --provider orcarouter --auth api-key     # paste an sk-orca-... key
    veil proxy --provider orcarouter --auth pkce        # Connect with OrcaRouter (OAuth 2.0 + PKCE)
    veil provider orcarouter                            # check credentials + live model catalog

Both authentication entries produce the same thing: a durable OrcaRouter API
key (`sk-orca-...`) held in veil's existing secret store (OS keychain, or the
0600 file fallback under $VEIL_HOME/keys). Inference then sends that key as a
Bearer token to https://api.orcarouter.ai/v1, OpenAI wire format.

Two origins, never derived from each other:
  auth / code exchange   ORCA_AUTH_BASE_URL > ORCA_BASE_URL > https://www.orcarouter.ai
  inference / catalog    ORCA_API_BASE_URL  > ORCA_BASE_URL > https://api.orcarouter.ai/v1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from typing import Callable

import httpx

PROVIDER_ID = "orcarouter"
PROVIDER_NAME = "OrcaRouter Cyber Inference"
EXAMPLES_URL = "https://www.orcarouter.ai/cyber"
CATALOG_URL = "https://www.orcarouter.ai/models?tier=cyber"
LOGO_URL = "https://www.orcarouter.ai/orca-logo-classic.png"

DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"
AUTHORIZE_PATH = "/auth"                 # browser consent screen (auth origin)
EXCHANGE_PATH = "/api/v1/auth/keys"      # NOT /v1/auth/keys, NOT on the api origin
APP_NAME = "veil"

DEFAULT_MODEL = "orcarouter/auto"        # default: automatic routing, works with any key
FUSION_MODEL = "orcarouter/fusion"       # general fallback
CYBER_MODELS = ("orcacyber-ultra-1.0", "orcacyber-zero-1.5", "orcacyber-zero-1.0")

KEY_ENV = "ORCA_KEY"                     # an existing key picked up from the environment
KEY_NAME = "orcarouter-api-key"          # name inside veil's key store (keys.py)
LEGACY_PREFIX = "sk-orca-"               # format hint only: not proof of validity

CATALOG_TIMEOUT = 20.0
CATALOG_MAX_BYTES = 4 * 1024 * 1024
CATALOG_MAX_ITEMS = 5000

# Verified cold-start seed: used only when live discovery fails. Live discovery,
# once it succeeds, is authoritative and replaces this entirely. Capabilities
# come from the catalog metadata these entries are known to carry (text chat,
# reasoning ladder for gpt-5.5); nothing here is inferred from a model name.
SEED_CATALOG: list[dict] = [
    {"id": "orcarouter/auto", "name": "OrcaRouter Auto", "context_length": 200000,
     "supported_endpoint_types": ["openai"], "input_modalities": ["text"],
     "reasoning": {"efforts": ["low", "medium", "high"]}},
    {"id": "openai/gpt-5.5", "name": "GPT-5.5", "context_length": 400000,
     "supported_endpoint_types": ["openai", "openai-response"], "input_modalities": ["text", "image"],
     "reasoning": {"efforts": ["low", "medium", "high", "xhigh"]}},
    {"id": "anthropic/claude-opus-4.8", "name": "Claude Opus 4.8", "context_length": 200000,
     "supported_endpoint_types": ["anthropic"], "input_modalities": ["text", "image"],
     "reasoning": {"efforts": ["low", "medium", "high"]}},
    {"id": "google/gemini-3.5-flash", "name": "Gemini 3.5 Flash", "context_length": 1000000,
     "supported_endpoint_types": ["gemini", "openai"], "input_modalities": ["text", "image", "audio", "video"],
     "reasoning": {"efforts": []}},
    {"id": "deepseek/deepseek-v4-pro", "name": "DeepSeek V4 Pro", "context_length": 128000,
     "supported_endpoint_types": ["openai"], "input_modalities": ["text"], "reasoning": {"efforts": []}},
    {"id": "orcarouter/fusion", "name": "OrcaRouter Fusion", "context_length": 200000,
     "supported_endpoint_types": ["openai"], "input_modalities": ["text"],
     "reasoning": {"efforts": []}},
]


class OrcaError(Exception):
    """A terminal, user-facing authentication or discovery failure."""


# -- origins ---------------------------------------------------------------------

def _origin(raw: str, what: str) -> str:
    u = urllib.parse.urlparse(raw.strip())
    loopback = u.hostname in ("127.0.0.1", "localhost", "::1")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise OrcaError(f"{what} must be an http(s) URL, got {raw!r}")
    if u.scheme != "https" and not loopback:
        raise OrcaError(f"{what} must use HTTPS for a remote origin (HTTP is allowed only for loopback)")
    return raw.strip().rstrip("/")


def auth_base(env: dict | None = None) -> str:
    e = os.environ if env is None else env
    return _origin(e.get("ORCA_AUTH_BASE_URL") or e.get("ORCA_BASE_URL") or DEFAULT_AUTH_BASE, "ORCA_AUTH_BASE_URL")


def api_base(env: dict | None = None) -> str:
    e = os.environ if env is None else env
    explicit = e.get("ORCA_API_BASE_URL")
    if explicit:  # either https://api.orcarouter.ai or .../v1
        origin = _origin(explicit, "ORCA_API_BASE_URL")
        return origin
    shared = e.get("ORCA_BASE_URL")
    if shared:  # a self-hosted deployment on one origin serves inference at /v1 too
        return _origin(shared, "ORCA_BASE_URL") + "/v1"
    return DEFAULT_API_BASE


def authorize_url(auth: str, callback_url: str, challenge: str, state: str, scope: str = "api") -> str:
    return auth + AUTHORIZE_PATH + "?" + urllib.parse.urlencode({
        "callback_url": callback_url, "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state, "app_name": APP_NAME, "scope": scope})


def exchange_url(auth: str) -> str:
    return auth + EXCHANGE_PATH


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# -- credentials -------------------------------------------------------------------

@dataclass(frozen=True)
class Credential:
    """What both authentication entries produce: the downstream only sees this."""
    key: str
    source: str                      # "api-key" | "pkce" | "env"
    generation: str = ""             # changes on every (re)connect of this credential
    scope: str = "api"
    account: str = ""                # user id from the exchange, if any
    needs_reauth: bool = False

    def masked(self) -> str:
        return LEGACY_PREFIX + "…" + self.key[-4:] if len(self.key) > len(LEGACY_PREFIX) + 4 else LEGACY_PREFIX + "…"

    def __repr__(self) -> str:       # never let a key reach a traceback or a log line
        return f"Credential(source={self.source!r}, {self.masked()}, needs_reauth={self.needs_reauth})"


def _store(env: dict | None):
    from . import keys
    from .state import home
    e = os.environ if env is None else env
    return keys, home()


def save_credential(cred: Credential, env: dict | None = None) -> str:
    """Persist in veil's existing secret store. Returns where it went ('env' = read-only)."""
    keys, h = _store(env)
    doc = json.dumps({"key": cred.key, "source": cred.source, "generation": cred.generation,
                      "scope": cred.scope, "account": cred.account, "needs_reauth": cred.needs_reauth})
    return keys.set_key(KEY_NAME, h, doc.encode())


def load_credential(env: dict | None = None) -> Credential | None:
    e = os.environ if env is None else env
    if e.get(KEY_ENV):
        return Credential(key=e[KEY_ENV].strip(), source="env", generation="env")
    keys, h = _store(env)
    raw = keys.peek_key(KEY_NAME, h)
    if not raw:
        return None
    doc = _parse_stored(raw.decode())
    return doc


def clear_credential(env: dict | None = None) -> bool:
    keys, h = _store(env)
    if keys.peek_key(KEY_NAME, h) is None:
        return False
    keys.delete_key(KEY_NAME, h)
    return True


def _parse_stored(text: str) -> Credential:
    try:
        doc = json.loads(text)
        if isinstance(doc, dict) and doc.get("veil") and doc.get("b64"):  # raw key stored by keys.set_key
            doc = {"key": base64.b64decode(doc["b64"]).decode()}
        if isinstance(doc, dict) and doc.get("key"):
            return Credential(key=doc["key"], source=doc.get("source", "api-key"), generation=doc.get("generation", ""),
                              scope=doc.get("scope", "api"), account=doc.get("account", ""),
                              needs_reauth=bool(doc.get("needs_reauth")))
    except ValueError:
        pass
    return Credential(key=text.strip(), source="api-key", generation="legacy")


def check_format(key: str) -> None:
    """Lightweight format check only: an sk-orca- prefix is not proof the key is valid."""
    if not key or not key.strip() or any(c.isspace() for c in key.strip()):
        raise OrcaError("an OrcaRouter API key is a single token starting with sk-orca-")


def connect_api_key(key: str, env: dict | None = None) -> Credential:
    """API-key adapter: the user pastes an existing sk-orca-... key."""
    key = (key or "").strip()
    check_format(key)
    if not key.startswith(LEGACY_PREFIX):
        raise OrcaError(f"OrcaRouter API keys start with {LEGACY_PREFIX}")
    cred = Credential(key=key, source="api-key", generation=secrets.token_hex(8))
    save_credential(cred, env)
    return cred


# -- OAuth 2.0 + PKCE --------------------------------------------------------------

@dataclass
class Pending:
    verifier: str
    challenge: str
    state: str
    auth: str
    scope: str

    def url(self, callback_url: str) -> str:
        return authorize_url(self.auth, callback_url, self.challenge, self.state, self.scope)


def new_pending(auth: str | None = None, scope: str = "api") -> Pending:
    verifier = b64url(secrets.token_bytes(32))          # fresh, crypto RNG, per attempt
    return Pending(verifier=verifier,
                   challenge=b64url(hashlib.sha256(verifier.encode()).digest()),
                   state=b64url(secrets.token_bytes(16)),
                   auth=auth or auth_base(), scope=scope)


def _oauth_error(status: int, body: dict) -> OrcaError:
    code = body.get("error") or body.get("code") or ""
    desc = body.get("error_description") or body.get("message") or ""
    if status == 403 or code in ("invalid_grant", "access_denied", "expired"):
        return OrcaError(f"authorization code rejected or expired (HTTP {status}); start Connect again"
                         + (f": {desc}" if desc else ""))
    if status == 400:
        return OrcaError(f"authorization request refused (HTTP 400)"
                         + (f": {desc}" if desc else "; PKCE method must match S256"))
    if status == 429:
        return OrcaError("OrcaRouter rate limit on key issuance (HTTP 429); at most 10 PKCE keys per user "
                         "per 24 hours -- reuse the stored key or try later")
    return OrcaError(f"OrcaRouter authentication failed (HTTP {status})" + (f": {desc}" if desc else ""))


def exchange(pending: Pending, code: str, http: httpx.Client | None = None) -> Credential:
    """Redeem a code at the auth origin. The verifier never leaves this call except in the body."""
    code = (code or "").strip()
    if not code:
        raise OrcaError("no authorization code was provided")
    client = http or _client(timeout=30)
    try:
        r = client.post(exchange_url(pending.auth), json={
            "code": code, "code_verifier": pending.verifier, "code_challenge_method": "S256"})
    except httpx.HTTPError as e:
        raise OrcaError(f"could not reach OrcaRouter authentication ({type(e).__name__}); nothing was changed") from None
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200 or not isinstance(body, dict) or not body.get("key"):
        raise _oauth_error(r.status_code, body if isinstance(body, dict) else {})
    granted = str(body.get("scope") or "")
    if granted != pending.scope:
        raise OrcaError(f"OrcaRouter granted scope {granted!r}, not {pending.scope!r}; ask the workspace "
                        "owner for that grant, or start Connect again")
    # do not delete anything on failure: the old secret is replaced only now, on success
    return Credential(key=body["key"], source="pkce", generation=secrets.token_hex(8), scope=granted,
                      account=str(body.get("user_id") or ""))


class _Loopback(http.server.HTTPServer):
    """Binds and serves immediately (plain HTTPServer binds, ThreadingHTTPServer binds lazily)."""
    daemon_threads = True

    def __init__(self, handler_cls):
        super().__init__(("127.0.0.1", 0), handler_cls)
        self.server_activate()



def _flow_a_json(query: dict, pending: Pending, auth: str, http) -> Credential:
    state = str(query.get("state") or "")
    if not state or not hmac.compare_digest(state, pending.state):
        raise OrcaError("state mismatch on the OrcaRouter callback; authorization cancelled")
    if query.get("error"):
        raise OrcaError(f"OrcaRouter authorization was not approved ({query['error']})")
    return exchange(pending, query.get("code", ""), http)


class _Callback(http.server.BaseHTTPRequestHandler):
    """The one loopback callback: records the query, answers the tab, and releases the flow."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path != "/cb":
            self.send_response(404)
            self.end_headers()
            return
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        state_ok = bool(query.get("state")) and hmac.compare_digest(str(query["state"]), self.server.pending.state)
        body = (b"<p>OrcaRouter authorization received. You can close this tab.</p>" if state_ok else
                b"<p>OrcaRouter authorization failed (state mismatch). Close this tab and try again.</p>")
        if self.server.got.is_set():   # exactly one callback is acted on
            return
        self.server.received = query   # bound to this request, not to a shared event
        self.server.got.set()
        self.send_response(200 if state_ok else 400)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.server.done.set()


def _listener(pending: Pending):
    # HTTPServer.__init__ already serves requests: bind the context before it can answer
    srv = _Loopback.__new__(_Loopback)
    srv.pending, srv.received, srv.delivered = pending, None, {}
    srv.got, srv.done = threading.Event(), threading.Event()
    http.server.HTTPServer.__init__(srv, ("127.0.0.1", 0), _Callback)
    srv.server_activate()
    return srv


def flow_a(pending: Pending, open_browser: Callable[[str], bool] | None = None,
           timeout: float = 300.0, http: httpx.Client | None = None,
           print_fn: Callable[[str], None] | None = None) -> Credential:
    """Flow A -- loopback redirect: veil runs on the user's machine and can listen on 127.0.0.1.

    One callback is accepted, then answered with a "close this tab" page; state is compared
    before the code is looked at."""
    import sys
    say = print_fn or (lambda s: print(s, file=sys.stderr))
    srv = _listener(pending)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        url = pending.url(f"http://127.0.0.1:{port}/cb")
        say("Opening your browser to authorize OrcaRouter. If it does not open, visit:\n  " + url)
        (open_browser or webbrowser.open)(url)
        got_event = srv.got
        if not srv.done.wait(timeout):
            raise OrcaError("timed out waiting for the OrcaRouter consent screen; run Connect again")
    finally:
        srv.done.wait(2)
        srv.shutdown()
        srv.server_close()
    got = dict(getattr(srv, "received") or {})
    state = str(got.get("state") or "")
    if not state or not hmac.compare_digest(state, pending.state):
        raise OrcaError("state mismatch on the OrcaRouter callback; authorization cancelled")
    if got.get("error"):
        raise OrcaError(f"OrcaRouter authorization was not approved ({got['error']})")
    return exchange(pending, got.get("code", ""), http)


def flow_b(pending: Pending, read_code: Callable[[str], str] | None = None,
           open_browser: Callable[[str], bool] | None = None, http: httpx.Client | None = None,
           print_fn: Callable[[str], None] | None = None) -> Credential:
    """Flow B -- out-of-band code: no redirect to receive (SSH, container, locked-down host)."""
    import sys
    say = print_fn or (lambda s: print(s, file=sys.stderr))
    url = pending.url("oob")
    say("Open this URL, approve, then paste the code OrcaRouter shows:\n  " + url)
    (open_browser or webbrowser.open)(url)
    code = (read_code or input)("Code: ")
    return exchange(pending, code, http)


def connect(flow: str = "a", http: httpx.Client | None = None, env: dict | None = None,
            open_browser: Callable[[str], bool] | None = None,
            read_code: Callable[[str], str] | None = None,
            print_fn: Callable[[str], None] | None = None, timeout: float = 300.0,
            pending: Pending | None = None) -> Credential:
    """PKCE adapter: behaves like connect_api_key from the caller's point of view.

    A caller that already built a Pending (e.g. a UI showing the authorize URL) passes it in."""
    if pending is None:
        pending = new_pending(auth_base(env))
    if flow == "a":
        cred = flow_a(pending, open_browser=open_browser, http=http, print_fn=print_fn, timeout=timeout)
    else:
        cred = flow_b(pending, read_code=read_code, open_browser=open_browser, http=http, print_fn=print_fn)
    save_credential(cred, env)
    return cred


def mark_reauth(cred: Credential, env: dict | None = None) -> Credential:
    """Terminal 401: mark this exact credential generation for reauthentication.

    Never triggers a refresh (a PKCE-issued key is durable, not refreshable) and only
    touches the store if the stored generation is still the one that made the request,
    so a late 401 cannot mark a freshly reconnected key as broken."""
    repo = Files(env)
    return repo.mark_needs_reauth(cred.generation)


# -- credential store wrapper (kept small so tests can stand in for the key store) --

class Files:
    def __init__(self, env: dict | None = None):
        self.env = env

    def load(self) -> Credential | None:
        return load_credential(self.env)

    def save(self, cred: Credential) -> str:
        return save_credential(cred, self.env)

    def clear(self) -> bool:
        return clear_credential(self.env)

    def mark_needs_reauth(self, generation: str) -> Credential:
        cur = self.load()
        if cur is None or (generation and cur.generation != generation):
            return cur or Credential(key="", source="none")
        cur = Credential(key=cur.key, source=cur.source, generation=cur.generation, scope=cur.scope,
                         account=cur.account, needs_reauth=True)
        self.save(cur)
        return cur


def uses_env_key() -> bool:
    return bool(os.environ.get(KEY_ENV))


def requires_login(cred: Credential | None) -> bool:
    return cred is None or cred.needs_reauth


def describe(cred: Credential | None) -> dict:
    """Status for `veil provider` / `--print-config`: masked, never the key."""
    if cred is None:
        return {"provider": PROVIDER_ID, "name": PROVIDER_NAME, "configured": False,
                "hint": "veil provider orcarouter api-key (paste sk-orca-...) or --auth pkce"}
    return {"provider": PROVIDER_ID, "name": PROVIDER_NAME, "configured": not cred.needs_reauth,
            "auth": cred.source, "key": cred.masked(), "scope": cred.scope,
            "needs_reauth": cred.needs_reauth}


# -- model discovery ---------------------------------------------------------------

CHAT_ENDPOINTS = {"openai", "anthropic", "gemini", "openai-response"}
NON_TEXT_ENDPOINTS = {"image-generation", "openai-video", "jina-rerank", "embeddings"}


def _norm_entry(raw: dict) -> dict | None:
    """Accept the catalog's record shape; drop anything we could not speak."""
    if not isinstance(raw, dict):
        return None
    mid = raw.get("id")
    if not isinstance(mid, str) or not mid or "/" not in mid or len(mid) > 200:
        return None
    arch = raw.get("architecture") if isinstance(raw.get("architecture"), dict) else {}
    eps = {str(e) for e in (raw.get("supported_endpoint_types") or []) if isinstance(e, str)}
    mods = {str(m) for m in (arch.get("input_modalities") or raw.get("input_modalities") or []) if isinstance(m, str)}
    ctx = raw.get("context_length") or arch.get("context_length") or 0
    reasoning = raw.get("reasoning") if isinstance(raw.get("reasoning"), dict) else {}
    efforts = [e for e in (reasoning.get("efforts") or []) if isinstance(e, str)]
    return {"id": mid, "name": str(raw.get("name") or mid)[:120], "context_length": int(ctx) if isinstance(ctx, int) else 0,
            "supported_endpoint_types": sorted(eps), "input_modalities": sorted(mods),
            "reasoning": {"efforts": efforts}}


def parse_catalog(payload) -> list[dict]:
    data = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(data, list):
        raise OrcaError("model catalog response has no `data` list")
    out, seen = [], set()
    for raw in data[:CATALOG_MAX_ITEMS]:
        m = _norm_entry(raw)
        if m and m["id"] not in seen:
            seen.add(m["id"]); out.append(m)
    return out


def _client(**kw) -> httpx.Client:
    """Never use environment proxies: a proxy meant for git or another provider must not
    intercept the code exchange or the model catalog."""
    kw["trust_env"] = False
    return httpx.Client(**kw)


def _seed(note: str) -> tuple[list[dict], bool, str]:
    """Outage path: the small verified seed, clearly marked degraded. Never free text."""
    return [dict(m) for m in SEED_CATALOG], False, note


def discover(http: httpx.Client | None = None, cred: Credential | None = None, env: dict | None = None,
             timeout: float = CATALOG_TIMEOUT) -> tuple[list[dict], bool, str]:
    """GET {api_base}/models with the user's key. Returns (models, live, note).

    Bounded in time, bytes and item count; never falls back to free text."""
    base = api_base(env)
    url = base + "/models"
    headers = {"authorization": f"Bearer {cred.key}", "accept": "application/json"} if cred and cred.key else \
        {"accept": "application/json"}
    client = http or _client(timeout=timeout)
    try:
        with client.stream("GET", url, headers=headers) as r:
            buf = b""
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > CATALOG_MAX_BYTES:
                    return _seed("catalog too large; using verified fallback")
            status = r.status_code
    except httpx.HTTPError as e:
        return _seed(f"catalog unreachable ({type(e).__name__}); using verified fallback")
    if status in (401, 403):
        return [], False, f"model catalog refused the key (HTTP {status}); reconnect or replace the key"
    if status != 200:
        return _seed(f"catalog returned HTTP {status}; using verified fallback")
    try:
        models = parse_catalog(json.loads(buf or b"{}"))
    except (ValueError, OrcaError) as e:
        return _seed(f"catalog unreadable ({type(e).__name__}); using verified fallback")
    if not models:
        return _seed("catalog empty; using verified fallback")
    return models, True, f"{len(models)} models from {url}"


def _is_text_chat(m: dict) -> bool:
    eps = set(m.get("supported_endpoint_types") or [])
    return bool(eps & CHAT_ENDPOINTS) and not (eps and eps <= NON_TEXT_ENDPOINTS)


def filter_capability(models: list[dict], capability: str, modalities: set[str] | None = None) -> list[dict]:
    """Options for one model selector. Chat first; multimodal requires a declared input modality
    (fail closed: an entry that does not declare `image` never appears in an image selector)."""
    if capability in ("chat", "multimodal"):
        out = [m for m in models if _is_text_chat(m)]
        if capability == "multimodal":
            need = set(modalities or {"image"})
            out = [m for m in out if need <= set(m.get("input_modalities") or [])]
        return [dict(m) for m in out]
    strict = {"embedding": {"embeddings"}, "image": {"image-generation"},
              "video": {"openai-video"}, "rerank": {"jina-rerank"}}.get(capability)
    if strict is None:
        return []
    return [dict(m) for m in models if set(m.get("supported_endpoint_types") or []) & strict]


def requires_multimodal(capability: str) -> bool:
    return capability == "multimodal"


def selector_options(models: list[dict], capability: str = "chat", selected: str | None = None,
                     modalities: set[str] | None = None, live: bool = True, degraded: str = "") -> dict:
    """What a model control binds to. An incompatible retained value is cleared, never silently kept."""
    opts = filter_capability(models, capability, modalities)
    ids = [m["id"] for m in opts]
    return {"capability": capability, "live": live, "degraded": degraded, "options": opts,
            "models": ids, "selected": selected if selected in ids else None,
            "cleared": selected is not None and selected not in ids}


def reasoning_efforts(models: list[dict], model_id: str) -> list[str]:
    for m in models:
        if m["id"] == model_id:
            return list((m.get("reasoning") or {}).get("efforts") or [])
    return []


# -- request helpers used by the proxy ----------------------------------------------

def request_url(base: str, path: str) -> str:
    return base.rstrip("/") + (path if path.startswith("/") else "/" + path)


def strip_client_auth(headers: dict) -> dict:
    """The client's own key (e.g. a leftover ANTHROPIC_AUTH_TOKEN) must not ride along:
    one request carries exactly one credential, the OrcaRouter one."""
    return {k: v for k, v in headers.items() if k.lower() not in ("authorization", "x-api-key")}


def auth_headers(cred: Credential) -> dict:
    return {"authorization": f"Bearer {cred.key}"}


def provider_upstreams() -> dict:
    base = api_base()
    return {"openai": base, "anthropic": base, "bedrock": None, "vertex": None}
