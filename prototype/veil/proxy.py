"""Local Anthropic-format proxy: point ANTHROPIC_BASE_URL at it.

    veil proxy --port 8787 &
    ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude

Every byte of context passes through here, so this is the enforcement layer:
it fails closed (a redaction error returns 502, never forwards raw data).
Headers are forwarded verbatim (anthropic-beta carries OAuth capabilities for
claude.ai logins); only hop-by-hop and encoding headers are dropped.
"""

from __future__ import annotations

import json
import socketserver
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from .anthropic import Policy, StreamRewriter, redact_request, rehydrate_response
from .engine import Veil
import dataclasses

from . import cloud, display, quasi
from .guard import Guard
from .openai import ChatStreamRewriter, is_chat_path, redact_chat_request, rehydrate_chat_response
from .responses import (ResponsesStreamRewriter, is_responses_path, redact_responses_request,
                        rehydrate_responses_body)

HOP = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive"}


class LocalHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse-DNS lookup in server_bind():
    http.server calls socket.getfqdn(host), which can stall for 30 s+ on macOS
    (mDNS). veil binds loopback only, so the name is just the address."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def make_handler(veil: Veil, policy: Policy, upstream: str, client: httpx.Client, log=sys.stderr,
                 observer=None, openai_upstream: str | None = None, bedrock_upstream: str | None = None,
                 vertex_upstream: str | None = None, foundry_upstream: str | None = None,
                 anthropic_aws_upstream: str | None = None):
    """`observer(exchange)` (optional) receives one dict per request: path, safe headers,
    `original` body, `sent` body (exact upstream payload), `model_view` (the model's
    reply before rehydration), status, findings and timings. For audits and tests."""
    guard = Guard(veil)
    guard_lock = threading.Lock()
    quasi_monitor = quasi.Monitor()
    try:  # create the hook secret up front so the first hook call can use the fast path
        from .hooks import hook_secret
        from .state import home
        hook_secret(home())
    except OSError:
        pass

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep stderr quiet; audit lines only
            pass

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass  # client closed a keep-alive connection

        def _fail(self, status: int, msg: str):
            body = json.dumps({"type": "error", "error": {"type": "veil_error", "message": msg}}).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("x-should-retry", "false")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _local_only(self) -> bool:
            # /veil/* endpoints: refuse anything not addressed to loopback (DNS-rebinding guard)
            host = (self.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
            if host not in ("127.0.0.1", "localhost", "::1"):
                self._fail(403, "veil: local endpoints only")
                return False
            return True

        def _hook(self, raw: bytes):
            if not self._local_only():
                return
            import hmac
            from .hooks import hook_response, hook_secret
            from .state import home
            if not hmac.compare_digest(self.headers.get("x-veil-hook-secret", ""), hook_secret(home())):
                return self._fail(403, "veil: bad hook secret")
            try:
                with guard_lock:
                    out = hook_response(veil, self.path.rsplit("/", 1)[-1], json.loads(raw or b"{}"))
            except Exception as e:
                return self._fail(500, f"veil hook error: {type(e).__name__}")
            body = json.dumps(out, ensure_ascii=False).encode() if out else b""
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.split("?")[0] == "/veil/health":  # local only; never values
                if not self._local_only():
                    return
                body = json.dumps({"ok": True, "upstream": upstream, "known_values": len(veil.known),
                                   "display": display.resolve(self.headers, home(), not policy.display_real),
                                   "sources": len(getattr(getattr(veil, "reseeder", None), "sources", [])),
                                   "reseed_passes": getattr(getattr(veil, "reseeder", None), "runs", 0),
                                   "quasi": quasi.mode(home()), "quasi_reported": len(quasi_monitor.seen),
                                   "tokens": len(veil.vault.tokens()), "ner": veil.ner is not None}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._forward(None)

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("content-length") or 0))
            if self.path.split("?")[0] in ("/veil/hook/pre", "/veil/hook/post"):
                veil.quasi_mode = quasi.mode(home())
                return self._hook(raw)
            self._forward(raw)

        def _forward(self, raw: bytes | None):
            exch = {"path": self.path, "original": None, "sent": None, "model_view": None,
                    "status": None, "findings": [], "veil_ms": 0.0, "upstream_ms": 0.0,
                    "headers": {k.lower(): v for k, v in self.headers.items()
                                if k.lower() in ("anthropic-version", "anthropic-beta", "user-agent")}}
            try:
                self._exchange(raw, exch)
            finally:
                if observer and exch["original"] is not None:
                    observer(exch)

        def _exchange(self, raw: bytes | None, exch: dict):
            # display mode is resolved per request: `veil display tokens` and the managed
            # x-veil-display header take effect immediately (see veil/display.py)
            mode = display.resolve(self.headers, home(), forced_tokens=not policy.display_real)
            self.pol = dataclasses.replace(policy, display_real=mode == "real")
            exch["display"] = mode
            veil.quasi_mode = quasi.mode(home())
            provider, path = cloud.split_prefix(self.path)  # /foundry/..., /anthropic-aws/...
            provider_upstream = {"foundry": foundry_upstream, "anthropic-aws": anthropic_aws_upstream}.get(provider)
            if provider and not provider_upstream:
                return self._fail(404, f"veil: no upstream configured for {provider} (--{provider}-upstream)")
            api = "anthropic" if path.split("?")[0].startswith("/v1/messages") else \
                ("chat" if is_chat_path(path) else ("responses" if is_responses_path(path) else cloud.route(path)))
            is_messages = api is not None
            target = provider_upstream or {"chat": openai_upstream, "responses": openai_upstream,
                                           "bedrock": bedrock_upstream, "vertex": vertex_upstream}.get(api, upstream)
            if api in ("chat", "responses", "bedrock", "vertex") and not target:
                return self._fail(404, f"veil: no upstream configured for {api} (--{'openai' if api in ('chat', 'responses') else api}-upstream)")
            if api is None and not provider and (bedrock_upstream or vertex_upstream) and not path.startswith("/v1/"):
                target = bedrock_upstream or vertex_upstream  # e.g. Bedrock GET /inference-profiles
            body_bytes = raw
            stream = False
            if raw and is_messages:
                try:
                    t0 = time.perf_counter()
                    veil.vault.refresh()  # tokens allocated by hook processes since the last request
                    body = json.loads(raw)
                    exch["original"] = body
                    before = veil.vault.version
                    body = {"anthropic": redact_request, "chat": redact_chat_request,
                            "responses": redact_responses_request, "bedrock": redact_request,
                            "vertex": redact_request}[api](veil, body, notice=self.pol.notice)
                    with guard_lock:
                        body, findings = guard.enforce(body)
                    exch["findings"] = [f.__dict__ for f in findings]
                    for f in findings:  # path/kind/token only, never the real value
                        state = "repaired" if f.repaired else ("WARNING model-output" if f.allowed else "BLOCKED")
                        print(f"[veil-guard] {state} {f.kind} ({f.form}) at {f.path} -> {f.token}", file=log)
                    blocked = [f for f in findings if not f.repaired and not f.allowed]
                    if blocked:
                        exch["status"] = "blocked by veil"
                        return self._fail(400, f"veil blocked request: {len(blocked)} real value(s) in "
                                               f"unrepairable field(s): {sorted({f.path for f in blocked})}")
                    if veil.quasi_mode == "warn":
                        warning = quasi_monitor.check(veil.known, _strings(body.get("messages") or body.get("input")))
                        if warning:
                            exch["quasi"] = warning
                            print(f"[veil] {warning}", file=log)
                    stream = bool(body.get("stream"))
                    body_bytes = json.dumps(body, ensure_ascii=False).encode()
                    exch["sent"] = body
                    exch["veil_ms"] = (time.perf_counter() - t0) * 1000
                    print(f"[veil] {path} new_tokens={veil.vault.version - before} "
                          f"vault={len(veil.vault.tokens())}", file=log)
                except Exception as e:  # fail closed; log code locations only (messages may hold data)
                    import traceback
                    frames = " <- ".join(f"{os.path.basename(f.filename)}:{f.lineno}:{f.name}"
                                         for f in reversed(traceback.extract_tb(e.__traceback__)))
                    print(f"[veil] redaction error {type(e).__name__} at {frames}", file=log)
                    return self._fail(502, f"veil could not redact request: {type(e).__name__}")
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP and k.lower() != display.HEADER}
            headers["accept-encoding"] = "identity"
            url = (target or upstream).rstrip("/") + path
            if api == "bedrock" or (api is None and target == bedrock_upstream and bedrock_upstream):
                headers = cloud.bedrock_auth(self.command, url, headers, body_bytes)  # signs the *redacted* body
            elif api == "vertex":
                headers = cloud.vertex_auth(headers)
            elif provider == "foundry":
                headers = cloud.foundry_auth(headers)
            elif provider == "anthropic-aws":
                headers = cloud.anthropic_aws_auth(self.command, url, headers, body_bytes)
            req = client.build_request(self.command, url, headers=headers, content=body_bytes)
            t1 = time.perf_counter()
            resp = client.send(req, stream=True)
            exch["status"] = resp.status_code
            try:
                ctype = resp.headers.get("content-type", "")
                self.send_response(resp.status_code)
                for k, v in resp.headers.items():
                    if k.lower() not in HOP:
                        self.send_header(k, v)
                if api == "bedrock" and resp.status_code == 200 and "eventstream" in ctype:
                    self.send_header("transfer-encoding", "chunked")
                    self.end_headers()
                    exch["model_view"] = self._relay_eventstream(resp)
                elif is_messages and resp.status_code == 200 and stream and "event-stream" in ctype:
                    self.send_header("transfer-encoding", "chunked")
                    self.end_headers()
                    exch["model_view"] = {"anthropic": self._relay_sse, "vertex": self._relay_sse,
                                          "chat": self._relay_chat_sse,
                                          "responses": self._relay_responses_sse}[api](resp)
                else:
                    data = resp.read()
                    if is_messages and resp.status_code == 200 and "json" in ctype \
                            and not path.split("?")[0].endswith("count_tokens") and not cloud.is_count_tokens(path):
                        exch["model_view"] = json.loads(data)
                        rehydrate = {"anthropic": rehydrate_response, "bedrock": rehydrate_response,
                                     "vertex": rehydrate_response, "chat": rehydrate_chat_response,
                                     "responses": rehydrate_responses_body}[api]
                        data = json.dumps(rehydrate(veil, self.pol, exch["model_view"]),
                                          ensure_ascii=False).encode()
                    elif resp.status_code != 200:
                        exch["model_view"] = {"error": data.decode(errors="replace")[:2000]}
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            finally:
                resp.close()
                exch["upstream_ms"] = (time.perf_counter() - t1) * 1000

        def _chunk(self, data: bytes):
            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()

        def _relay_eventstream(self, resp: httpx.Response) -> dict:
            """Bedrock: decode binary frames, rewrite the Anthropic event inside, re-encode with new CRCs."""
            rw = StreamRewriter(veil, self.pol)
            decoder = cloud.FrameDecoder()
            view: dict = {"content": [], "usage": {}, "stop_reason": None, "model": None}
            for data in resp.iter_bytes():
                for headers, payload in decoder.feed(data):
                    event = cloud.chunk_event(headers, payload)
                    if event is None:  # exceptions / other frames: pass through byte-identical
                        self._chunk(cloud.encode_frame({k: v for k, v in headers.items() if isinstance(v, str)}, payload))
                        continue
                    _accumulate(view, event)
                    for _, out in rw.feed(event.get("type", ""), event):
                        self._chunk(cloud.chunk_frame(out))
            self._chunk(b"")
            return view

        def _relay_responses_sse(self, resp: httpx.Response) -> dict:
            """Responses API stream: `event: <type>` + `data: {json}` frames."""
            rw = ResponsesStreamRewriter(veil, self.pol)
            event, datas = None, []
            for line in resp.iter_lines():
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    datas.append(line[5:].lstrip())
                elif line == "" and datas:
                    payload = "\n".join(datas)
                    try:
                        evs = rw.feed(json.loads(payload))
                        frame = "".join(f"event: {e.get('type', event)}\ndata: {json.dumps(e, ensure_ascii=False)}\n\n"
                                        for e in evs)
                    except json.JSONDecodeError:
                        frame = (f"event: {event}\n" if event else "") + f"data: {payload}\n\n"
                    if frame:
                        self._chunk(frame.encode())
                    event, datas = None, []
            self._chunk(b"")
            return rw.view

        def _relay_chat_sse(self, resp: httpx.Response) -> dict:
            """OpenAI chat stream: `data: {chunk}` ... `data: [DONE]`."""
            rw = ChatStreamRewriter(veil, self.pol)
            for line in resp.iter_lines():
                if not line.startswith("data:"):
                    if line.startswith(":"):  # SSE comment / keep-alive
                        self._chunk((line + "\n\n").encode())
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    self._chunk(b"data: [DONE]\n\n")
                    continue
                try:
                    chunks = rw.feed(json.loads(payload))
                except json.JSONDecodeError:
                    self._chunk(f"data: {payload}\n\n".encode())
                    continue
                for c in chunks:
                    self._chunk(f"data: {json.dumps(c, ensure_ascii=False)}\n\n".encode())
            self._chunk(b"")
            return rw.view

        def _relay_sse(self, resp: httpx.Response) -> dict:
            """Relay + rewrite the stream; returns the model's own (tokenized) message."""
            rw = StreamRewriter(veil, self.pol)
            view: dict = {"content": [], "usage": {}, "stop_reason": None, "model": None}
            event, datas = None, []
            for line in resp.iter_lines():
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    datas.append(line[5:].lstrip())
                elif line == "" and datas:
                    payload = "\n".join(datas)
                    try:
                        data = json.loads(payload)
                        _accumulate(view, data)
                        out = rw.feed(event or "", data)
                        frame = "".join(f"event: {e}\ndata: {json.dumps(d, ensure_ascii=False)}\n\n" for e, d in out)
                    except json.JSONDecodeError:
                        frame = (f"event: {event}\n" if event else "") + f"data: {payload}\n\n"
                    if frame:
                        self._chunk(frame.encode())
                    event, datas = None, []
            self._chunk(b"")
            return view

    return Handler


def _accumulate(view: dict, ev: dict) -> None:
    t = ev.get("type")
    if t == "message_start":
        view["model"] = ev["message"].get("model")
        view["usage"].update(ev["message"].get("usage") or {})
    elif t == "content_block_start":
        cb = dict(ev["content_block"])
        if cb.get("type") == "tool_use":
            cb["_json"] = ""
        view["content"].append(cb)
    elif t == "content_block_delta" and view["content"]:
        cb, d = view["content"][-1], ev["delta"]
        if d.get("type") == "text_delta":
            cb["text"] = cb.get("text", "") + d["text"]
        elif d.get("type") == "input_json_delta":
            cb["_json"] += d.get("partial_json", "")
        elif d.get("type") == "thinking_delta":
            cb["thinking"] = cb.get("thinking", "") + d["thinking"]
    elif t == "content_block_stop" and view["content"]:
        cb = view["content"][-1]
        if "_json" in cb:
            try:
                cb["input"] = json.loads(cb.pop("_json") or "{}")
            except json.JSONDecodeError:
                cb["input"] = {"_unparsed": cb.pop("_json")}
    elif t == "message_delta":
        view["stop_reason"] = ev.get("delta", {}).get("stop_reason")
        view["usage"].update(ev.get("usage") or {})


def capture_observer(directory: str):
    """Write what the model saw (upstream payload + its reply, tokens only) per request."""
    import itertools
    import os
    os.makedirs(directory, mode=0o700, exist_ok=True)
    counter = itertools.count(len(os.listdir(directory)) // 2 + 1)
    lock = threading.Lock()

    def observe(exch: dict) -> None:
        if exch.get("sent") is None:
            return
        with lock:
            n = next(counter)
        for suffix, obj in (("sent", exch["sent"]), ("reply", exch.get("model_view"))):
            with open(os.path.join(directory, f"{n:05d}_{suffix}.json"), "w") as f:
                json.dump(obj, f, ensure_ascii=False, indent=1)
    return observe


def serve(veil: Veil, policy: Policy, port: int = 8787, upstream: str = "https://api.anthropic.com",
          capture: str | None = None, openai_upstream: str | None = None, bedrock_upstream: str | None = None,
          vertex_upstream: str | None = None, foundry_upstream: str | None = None,
          anthropic_aws_upstream: str | None = None):
    client = httpx.Client(timeout=httpx.Timeout(600, connect=10))
    observer = capture_observer(capture) if capture else None
    server = LocalHTTPServer(("127.0.0.1", port), make_handler(veil, policy, upstream, client,
                                                                   observer=observer,
                                                                   openai_upstream=openai_upstream,
                                                                   bedrock_upstream=bedrock_upstream,
                                                                   vertex_upstream=vertex_upstream,
                                                                   foundry_upstream=foundry_upstream,
                                                                   anthropic_aws_upstream=anthropic_aws_upstream))
    print(f"[veil] listening on http://127.0.0.1:{port} -> {upstream}", file=sys.stderr)
    return server
