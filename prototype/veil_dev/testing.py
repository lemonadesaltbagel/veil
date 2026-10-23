"""Audit/test harness: sample data, a scripted fake LLM, a recording proxy, and
reports of exactly what an LLM call received.

The fake model only knows what it was sent. It behaves like an agent model:
take the email from the user's prompt, query the DB for it with Bash, read
app.log in the working directory, then summarise. If veil leaked anything, the
fake model would put the *real* value into its own commands, and the leak scan
over the recorded upstream payloads would catch it.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from veil.proxy import LocalHTTPServer
from veil.anthropic import Policy
from veil.detect import WORD
from veil.engine import Veil
from veil.proxy import make_handler

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CWD = re.compile(r'(?:Primary working directory:\s*|"(?:live_cwd|cwd)":\s*")([^"\s\\]+)', re.I)
# Anything shaped like a veil token; used to spot tokens the model mangled or invented.
TOKEN_SHAPE = re.compile(r"\b(?:(?:user|USER|User|First|Last|card|secret)_[A-Za-z2-9]{3,6}|User [A-Z2-9][a-z2-9]{3,5})\b(?:@example\.test)?")

PROMPT = ("Customer Leonie Köhler (leonekohler@surfeu.de, +49 0711 2842222) says her last invoice was "
          "charged twice. Check chinook.sqlite and app.log and tell me what happened.")
EXTRA_REAL_VALUES = ["priya.raman@gmail.com", "84.191.20.7", "4111 1111 1111 1111", "+1 650-555-0199",
                     "sk_live_EXAMPLE_ONLY_dGhpcyBpcyBub3QgcmVhbA",
                     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZW9uZSJ9.c2lnbmF0dXJlX2V4YW1wbGU"]


# -- sample workspace ------------------------------------------------------

def make_app_log(db: str, path: str) -> None:
    """A realistic billing log built from real Chinook rows, plus PII that is
    *not* in the DB (a support engineer's email, a stray phone, secrets)."""
    con = sqlite3.connect(db)
    rows = con.execute("""
        select c.FirstName || ' ' || c.LastName, c.Email, c.Phone, i.InvoiceId, i.Total, i.BillingAddress
        from Customer c join Invoice i using (CustomerId)
        where c.CustomerId in (2, 4, 7, 15, 31, 44) order by i.InvoiceDate desc limit 14""").fetchall()
    out = []
    for n, (name, email, phone, inv, total, addr) in enumerate(rows):
        ts = f"2026-10-{10 + n // 3:02d}T0{n % 10}:1{n % 6}:0{n % 9}Z"
        out.append(f'{ts} INFO  billing.charge ok invoice={inv} amount={total} customer="{name}" email={email}')
        if email.startswith("leonekohler"):
            out.append(f'{ts} WARN  billing.charge duplicate invoice={inv} amount={total} customer="{name}" '
                       f'email={email} card=4111 1111 1111 1111 ship_to="{addr}" ip=84.191.20.7')
            out.append(f'{ts} INFO  support.ticket opened by {email} phone="{phone}" '
                       f'assigned=priya.raman@gmail.com (+1 650-555-0199)')
    out.append(f"2026-10-15T09:00:00Z DEBUG stripe key={EXTRA_REAL_VALUES[4]} reloaded")
    out.append(f"2026-10-15T09:00:01Z ERROR jwt verify failed token={EXTRA_REAL_VALUES[5]}")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


# -- recording -------------------------------------------------------------

class Recorder:
    """Proxy observer: one dict per exchange (see proxy.make_handler)."""

    def __init__(self):
        self.exchanges: list[dict] = []
        self.lock = threading.Lock()

    def __call__(self, exchange: dict) -> None:
        with self.lock:
            self.exchanges.append(exchange)

    def messages(self) -> list[dict]:
        return [e for e in self.exchanges if "count_tokens" not in e["path"]]


def start_proxy(veil: Veil, upstream: str, recorder: Recorder, policy: Policy | None = None,
                log=None, openai_upstream: str | None = None, bedrock_upstream: str | None = None,
                vertex_upstream: str | None = None, foundry_upstream: str | None = None,
                anthropic_aws_upstream: str | None = None) -> ThreadingHTTPServer:
    client = httpx.Client(trust_env=False, timeout=httpx.Timeout(300, connect=15))
    server = LocalHTTPServer(("127.0.0.1", 0), make_handler(
        veil, policy or Policy(), upstream, client, log=log or open(os.devnull, "w"), observer=recorder,
        openai_upstream=openai_upstream or upstream, bedrock_upstream=bedrock_upstream or upstream,
        vertex_upstream=vertex_upstream or upstream, foundry_upstream=foundry_upstream or upstream,
        anthropic_aws_upstream=anthropic_aws_upstream or upstream))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# -- fake model ------------------------------------------------------------

def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if b.get("type") == "text":
            out.append(b["text"])
        elif b.get("type") == "tool_result":
            out.append(_text_of(b.get("content")))
    return "\n".join(out)


def model_turn(body: dict, db_path: str = "chinook.sqlite") -> list[dict]:
    """The fake model's decision for one request -> list of content blocks."""
    msgs = body.get("messages", [])
    if not body.get("tools") or not msgs:
        return [{"type": "text", "text": "ok"}]
    first_user = _text_of(msgs[0]["content"])
    results = [b for m in msgs if isinstance(m["content"], list)
               for b in m["content"] if b.get("type") == "tool_result"]
    tools = {t.get("name") for t in body["tools"]}
    emails = EMAIL.findall(first_user)
    if not emails:
        return [{"type": "text", "text": "Which customer should I look at?"}]
    email = emails[-1]
    mcp_query = next((t for t in sorted(tools) if t and t.startswith("mcp__") and t.endswith("__query")), None)
    if mcp_query and not results:  # a database tool: the pseudonym goes in a string literal
        sql = ("SELECT c.FirstName, c.LastName, c.Email, c.Phone, i.InvoiceId, i.Total, i.BillingAddress "
               f"FROM Customer c JOIN Invoice i USING (CustomerId) WHERE c.Email = '{email}' "
               "ORDER BY i.InvoiceDate DESC LIMIT 3")
        return [{"type": "text", "text": f"Let me query the database for {email}."},
                {"type": "tool_use", "id": "toolu_mock_mcp", "name": mcp_query, "input": {"sql": sql}}]
    if mcp_query:
        last = _text_of(results[-1].get("content"))
        rows = [l for l in last.splitlines()[1:] if email in l]
        return [{"type": "text", "text": f"Summary for {email}: {len(rows)} invoice row(s) from the database.\n"
                 + "\n".join(rows)}]
    shell = "Bash" if "Bash" in tools else ("bash" if "bash" in tools else None)  # Claude Code | aliased lowercase tools
    reader = "Read" if "Read" in tools else ("read" if "read" in tools else None)
    if not results and shell:
        cmd = (f"sqlite3 -header {db_path} \"select c.FirstName, c.LastName, c.Email, c.Phone, "
               f"i.InvoiceId, i.InvoiceDate, i.Total, i.BillingAddress from Customer c join Invoice i "
               f"using (CustomerId) where c.Email = '{email}' order by i.InvoiceDate desc limit 3\"")
        return [{"type": "text", "text": f"Let me look up {email} in the database."},
                {"type": "tool_use", "id": "toolu_mock_1", "name": shell,
                 "input": {"command": cmd, "description": "Look up the customer's latest invoices"}}]
    if len(results) == 1 and reader:
        m = CWD.search(json.dumps(body, ensure_ascii=False))  # system prompt or safeguards context
        cwd = m.group(1) if m else "."
        return [{"type": "text", "text": "Now the application log."},
                {"type": "tool_use", "id": "toolu_mock_2", "name": reader,
                 "input": {"file_path": f"{cwd.rstrip('/')}/app.log"}}]
    last = _text_of(results[-1].get("content")) if results else ""
    seen = sorted(set(EMAIL.findall(last)) | {email})
    lines = [l for l in last.splitlines() if email in l][:3]
    return [{"type": "text", "text":
             f"Summary for {email}: found {len(lines)} matching log lines. "
             f"Identifiers I saw: {', '.join(seen)}.\n" + "\n".join(lines)}]


def _sse(blocks: list[dict], model: str) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in _anthropic_events(blocks, model)).encode()


def _anthropic_events(blocks: list[dict], model: str) -> list[dict]:
    evs = [{"type": "message_start", "message": {
        "id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            evs.append({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
            t = b["text"]
            # Small, uneven chunks so tokens get split across deltas like real streams.
            evs += [{"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": t[j:j + 5]}}
                    for j in range(0, len(t), 5)]
        else:
            evs.append({"type": "content_block_start", "index": i,
                        "content_block": {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}})
            js = json.dumps(b["input"])
            evs += [{"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": js[j:j + 9]}}
                    for j in range(0, len(js), 9)]
        evs.append({"type": "content_block_stop", "index": i})
        evs.append({"type": "ping"})
    stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
    evs += [{"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 10}},
            {"type": "message_stop"}]
    return evs


def start_mock_llm(db_path: str = "chinook.sqlite") -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status: int, ctype: str, data: bytes):
            self.send_response(status)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send(200, "application/json", b'{"data": [], "has_more": false}')

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("content-length") or 0))
            body = json.loads(raw) if raw else {}
            self.server.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, raw))
            if "count_tokens" in self.path:
                return self._send(200, "application/json", b'{"input_tokens": 1000}')
            blocks = model_turn(body, db_path)
            model = body.get("model", "mock")
            if body.get("stream"):
                return self._send(200, "text/event-stream", _sse(blocks, model))
            stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
            msg = {"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": blocks,
                   "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
            self._send(200, "application/json", json.dumps(msg).encode())

    server = LocalHTTPServer(("127.0.0.1", 0), H)
    server.requests = []  # (path, headers, raw body) as received: what an upstream would see
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# -- analysis --------------------------------------------------------------

def find_leaks(payload: str, values) -> list[str]:
    """Real values present in the payload, plainly or after undoing line wrapping /
    octal / hex / unicode escapes (identifier-bounded, like detection)."""
    from veil.decode import views
    texts = [payload]
    try:  # decode per JSON string so escapes inside values are seen as the model sees them
        strings = []
        _collect(json.loads(payload), strings)
        texts += [v for s in strings for v in views(s)]
    except ValueError:
        texts += views(payload)
    from veil.decode import deep_views, norm, squash
    found = {v for v in values for t in texts if re.search(f"(?<![{WORD}]){re.escape(v)}(?![{WORD}])", t)}
    # transformed forms (reversed, rot13, upper-cased, spaced out, hex, url, char codes)
    deep = [d for t in texts for d in deep_views(t)]
    words, chars = [v for m, v in deep if m == "w"], [v for m, v in deep if m == "c"]
    for v in values:
        if v in found or len(squash(v)) < 8:
            continue
        if any(norm(v) in d for d in words) or any(squash(v) in d for d in chars):
            found.add(v)
    return sorted(found)


def _collect(o, out: list) -> None:
    if isinstance(o, str):
        out.append(o)
    elif isinstance(o, list):
        for x in o:
            _collect(x, out)
    elif isinstance(o, dict):
        for x in o.values():
            _collect(x, out)


def ledger(veil: Veil, payload: str) -> list[tuple[str, str, int]]:
    """(real value, token, occurrences) for every token present in the payload."""
    pattern = veil.token_pattern()
    if pattern is None:
        return []
    counts: dict[str, int] = {}
    for m in pattern.finditer(payload):
        counts[m.group()] = counts.get(m.group(), 0) + 1
    return [(veil.vault.value_for(t) or "?", t, n) for t, n in sorted(counts.items(), key=lambda kv: -kv[1])]


def mangled_tokens(veil: Veil, model_text: str) -> list[str]:
    """Token-shaped strings in the model's output that are not real tokens
    (case changed, truncated, invented) -- these can't be rehydrated."""
    pattern = veil.token_pattern()
    whole = [(m.start(), m.end()) for m in pattern.finditer(model_text)] if pattern else []
    return sorted({m.group() for m in TOKEN_SHAPE.finditer(model_text)
                   if not veil.vault.is_token(m.group())
                   and not any(a <= m.start() and m.end() <= b for a, b in whole)})  # part of "First_X Last_X"


def dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def _system_text(body: dict | None) -> str:
    s = (body or {}).get("system") or ""
    return s if isinstance(s, str) else "\n".join(b.get("text", "") for b in s)


def _model_text(view: dict | None) -> str:
    parts = []
    for b in (view or {}).get("content", []):
        if b.get("type") == "text":
            parts.append(b.get("text", ""))
        elif b.get("type") == "tool_use":
            parts.append(f"[tool_use {b.get('name')}] {json.dumps(b.get('input'), ensure_ascii=False)}")
    return "\n".join(parts)


def write_captures(out_dir: str, veil: Veil, exchanges: list[dict], real_values, title: str) -> dict:
    """Write every exchange (client request, upstream payload, model reply) and a REPORT.md."""
    os.makedirs(out_dir, exist_ok=True)
    real_values = sorted(set(real_values), key=len, reverse=True)
    summary = {"requests": 0, "leaks": {}, "tokens": 0, "guard_repairs": 0, "blocked": 0,
               "mangled_tokens": [], "usage": {}, "veil_ms_max": 0.0}
    body: list[str] = []
    for i, e in enumerate(exchanges, 1):
        stem = f"{i:02d}_{'count_tokens' if 'count_tokens' in e['path'] else 'messages'}"
        for suffix, obj in (("client_sent", e["original"]), ("llm_received", e["sent"]),
                            ("llm_replied", e["model_view"])):
            if obj is not None:
                with open(os.path.join(out_dir, f"{stem}_{suffix}.json"), "w") as f:
                    f.write(dump(obj))
        summary["requests"] += 1
        summary["blocked"] += e["status"] == "blocked by veil"
        summary["guard_repairs"] += sum(1 for f in e["findings"] if f["repaired"])
        summary["model_output_warnings"] = summary.get("model_output_warnings", 0) + sum(
            1 for f in e["findings"] if f.get("allowed"))
        summary["veil_ms_max"] = max(summary["veil_ms_max"], round(e["veil_ms"], 1))
        sent = dump(e["sent"]) if e["sent"] is not None else ""
        leaks = find_leaks(sent, real_values)
        led = ledger(veil, sent)
        reply = _model_text(e["model_view"])
        mangled = mangled_tokens(veil, reply)
        summary["mangled_tokens"] += mangled
        summary["tokens"] += sum(n for *_, n in led)
        for k, v in ((e["model_view"] or {}).get("usage") or {}).items():
            if isinstance(v, int):
                summary["usage"][k] = summary["usage"].get(k, 0) + v
        if leaks:
            summary["leaks"][stem] = leaks
        model = (e["sent"] or {}).get("model")
        body += [f"## {i}. POST {e['path']} — model `{model}` → status {e['status']}", "",
                 f"- upstream payload: {len(sent):,} chars, {len((e['sent'] or {}).get('messages', []))} messages; "
                 f"veil {e['veil_ms']:.1f} ms, upstream {e['upstream_ms']:.0f} ms",
                 f"- **real values found in payload: {len(leaks)}**" + (f" → {leaks}" if leaks else ""),
                 f"- guard: {len(e['findings'])} finding(s)" + "".join(
                     f"\n  - {'repaired' if f['repaired'] else ('WARNING in model output' if f.get('allowed') else 'BLOCKED')}"
                     f" {f['kind']} ({f['form']}) at `{f['path']}`"
                     for f in e["findings"]),
                 f"- usage: `{json.dumps((e['model_view'] or {}).get('usage'))}`", ""]
        if led:
            body += ["| real value (stayed local) | token the LLM saw | × |", "|---|---|---|"]
            body += [f"| `{v}` | `{t}` | {n} |" for v, t, n in led[:25]]
            body += ([f"| … {len(led) - 25} more | | |"] if len(led) > 25 else []) + [""]
        before, after = _system_text(e["original"]), _system_text(e["sent"])
        if before != after:
            body += ["<details><summary>system prompt: before → after (tail)</summary>", "",
                     "```text", before[-1500:], "```", "", "```text", after[-1500:], "```", "", "</details>", ""]
        if reply:
            body += ["**Model reply, exactly as the model wrote it (tokens):**", "", "```text", reply[:3000], "```", ""]
            if mangled:
                body += [f"⚠️ token-shaped strings that are not valid tokens: {mangled}", ""]
    head = [f"# {title}", "",
            f"**{summary['requests']} requests · {sum(map(len, summary['leaks'].values()))} real values leaked · "
            f"{summary['tokens']} pseudonym occurrences · guard repairs {summary['guard_repairs']} · "
            f"blocked {summary['blocked']} · mangled tokens {len(summary['mangled_tokens'])}**", "",
            "Per request: `*_client_sent.json` (before veil), `*_llm_received.json` (exact upstream payload), "
            "`*_llm_replied.json` (model output before rehydration).", ""]
    with open(os.path.join(out_dir, "REPORT.md"), "w") as f:
        f.write("\n".join(head + body))
    return summary


# -- fake OpenAI Responses model (Codex) --------------------------------------------

def responses_turn(body: dict, db_path: str = "chinook.sqlite") -> list[dict]:
    """Codex-shaped fake model: exec_command sqlite3 -> exec_command grep -> answer."""
    items = body.get("input") or []
    users = [it for it in items if isinstance(it, dict) and it.get("role") == "user"]
    text = " ".join(p.get("text", "") for it in users for p in (it.get("content") or []) if isinstance(p, dict))
    outputs = [it for it in items if isinstance(it, dict) and it.get("type") == "function_call_output"]
    emails = [e for e in EMAIL.findall(text) if not e.endswith("@example.com")]
    if not emails:
        return [{"type": "message", "text": "Which customer?"}]
    email = emails[-1]
    if not outputs:
        return [{"type": "function_call", "name": "exec_command", "arguments": {"cmd":
                 f"sqlite3 -header {db_path} \"select c.FirstName, c.LastName, c.Email, i.InvoiceId, i.Total "
                 f"from Customer c join Invoice i using (CustomerId) where c.Email = '{email}' "
                 f"order by i.InvoiceDate desc limit 2\""}}]
    if len(outputs) == 1:
        return [{"type": "function_call", "name": "exec_command", "arguments": {"cmd": f"grep -n '{email}' app.log"}}]
    out = outputs[-1].get("output")
    out = out if isinstance(out, str) else json.dumps(out)
    lines = [l for l in out.splitlines() if email in l][:3]
    return [{"type": "message", "text": f"Found {len(lines)} log lines for {email}:\n" + "\n".join(lines)}]


def _responses_sse(blocks: list[dict], model: str, n: int) -> bytes:
    rid, output, evs = f"resp_{n}", [], []
    usage = {"input_tokens": 1, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 1,
             "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 2}
    base = {"id": rid, "object": "response", "created_at": 0, "model": model, "usage": usage}
    evs.append({"type": "response.created", "response": {**base, "status": "in_progress", "output": []}})
    for i, b in enumerate(blocks):
        if b["type"] == "message":
            iid, t = f"msg_{n}_{i}", b["text"]
            item = {"type": "message", "id": iid, "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": t, "annotations": []}]}
            evs += [{"type": "response.output_item.added", "output_index": i, "item": {**item, "status": "in_progress", "content": []}},
                    {"type": "response.content_part.added", "item_id": iid, "output_index": i, "content_index": 0,
                     "part": {"type": "output_text", "text": "", "annotations": []}}]
            evs += [{"type": "response.output_text.delta", "item_id": iid, "output_index": i, "content_index": 0,
                     "delta": t[j:j + 5]} for j in range(0, len(t), 5)]
            evs += [{"type": "response.output_text.done", "item_id": iid, "output_index": i, "content_index": 0, "text": t},
                    {"type": "response.content_part.done", "item_id": iid, "output_index": i, "content_index": 0,
                     "part": item["content"][0]},
                    {"type": "response.output_item.done", "output_index": i, "item": item}]
        else:
            iid, args = f"fc_{n}_{i}", json.dumps(b["arguments"])
            item = {"type": "function_call", "id": iid, "call_id": f"call_{n}_{i}", "name": b["name"],
                    "arguments": args, "status": "completed"}
            evs += [{"type": "response.output_item.added", "output_index": i, "item": {**item, "arguments": "", "status": "in_progress"}}]
            evs += [{"type": "response.function_call_arguments.delta", "item_id": iid, "output_index": i,
                     "delta": args[j:j + 9]} for j in range(0, len(args), 9)]
            evs += [{"type": "response.function_call_arguments.done", "item_id": iid, "output_index": i, "arguments": args},
                    {"type": "response.output_item.done", "output_index": i, "item": item}]
        output.append(item)
    evs.append({"type": "response.completed", "response": {**base, "status": "completed", "output": output}})
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in evs).encode()


def start_mock_responses(db_path: str = "chinook.sqlite") -> ThreadingHTTPServer:
    counter = {"n": 0}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            b = b'{"object": "list", "data": [{"id": "gpt-6", "object": "model"}]}'
            self.send_response(200); self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            counter["n"] += 1
            data = _responses_sse(responses_turn(body, db_path), body.get("model", "gpt-6"), counter["n"])
            self.send_response(200); self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)

    server = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server



# -- fake cloud providers (Bedrock eventstream, Vertex SSE) --------------------------

def start_mock_cloud(db_path: str = "chinook.sqlite") -> ThreadingHTTPServer:
    """Speaks Bedrock (`/model/{id}/invoke-with-response-stream`, binary eventstream) and
    Vertex (`...:streamRawPredict`, SSE) with the same scripted model as start_mock_llm."""
    from veil import cloud

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status, ctype, data):
            self.send_response(status); self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)

        def do_GET(self):  # Bedrock startup probes (inference profiles)
            self._send(200, "application/json", b'{"inferenceProfileSummaries": []}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            path = self.path.split("?")[0]
            if cloud.is_count_tokens(path):
                return self._send(200, "application/json", b'{"inputTokens": 1000, "input_tokens": 1000}')
            blocks = model_turn(body, db_path)
            model = "mock-cloud"
            if path.endswith("/invoke-with-response-stream"):
                data = b"".join(cloud.chunk_frame(e) for e in _anthropic_events(blocks, model))
                return self._send(200, "application/vnd.amazon.eventstream", data)
            if path.endswith(":streamRawPredict"):
                return self._send(200, "text/event-stream", _sse(blocks, model))
            stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
            msg = {"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": blocks,
                   "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
            self._send(200, "application/json", json.dumps(msg).encode())

    server = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
