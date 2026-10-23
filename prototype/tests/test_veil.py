import json
import os
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler

import httpx
from veil.proxy import LocalHTTPServer
import pytest

from veil.anthropic import Policy, StreamRewriter, redact_request, rehydrate_response, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.proxy import make_handler
from veil.sources import classify, seed_sqlite
from veil.vault import Vault

ALICE = {"username": "alice_w", "email": "alice@acme-corp.com", "full_name": "Alice Wong"}


@pytest.fixture
def veil():
    known = KnownValues()
    for k, v in ALICE.items():
        known.add(v, {"full_name": "name"}.get(k, k), group="users:1")
    known.add("bob_k", "username", group="users:2")
    return Veil(Vault(":memory:", b"test-secret"), known)


def real_values():
    return [*ALICE.values(), "bob_k"]


# -- core ------------------------------------------------------------------

def test_deterministic_and_grouped(veil):
    a = veil.redact("alice_w <alice@acme-corp.com> (Alice Wong)")
    other = Veil(Vault(":memory:", b"test-secret"), veil.known)
    assert other.redact("alice_w <alice@acme-corp.com> (Alice Wong)") == a
    user, email, name = veil.vault.tokens().keys()
    code = user.removeprefix("user_")
    assert email == f"user_{code}@example.test" and name == f"First_{code.capitalize()} Last_{code.capitalize()}"
    assert Veil(Vault(":memory:", b"other-secret"), veil.known).redact("alice_w") != veil.redact("alice_w")


def test_known_values_in_code_and_logs(veil):
    text = ('2026-10-01 ERROR login failed user=alice_w ip=8.8.8.8\n'
            'assert get_user("alice@acme-corp.com").name == "Alice Wong"\n'
            'malice_wrapper = bob_kernel  # must not match inside identifiers\n')
    out = veil.redact(text)
    for v in real_values() + ["8.8.8.8"]:
        assert v not in out.split("malice_wrapper")[0]
    assert "malice_wrapper = bob_kernel" in out
    assert veil.redact(out) == out  # idempotent: tokens are never re-redacted
    assert veil.rehydrate(out) == text


def test_pattern_rules_and_allowlist(veil):
    text = ("contact carol@gmail.com or +1 415-555-2671; card 4111 1111 1111 1111; "
            "not 4111 1111 1111 1112; test@example.com; host 10.0.0.5; key AKIAIOSFODNN7EXAMPLE")
    out = veil.redact(text)
    assert "carol@gmail.com" not in out and "415-555-2671" not in out
    assert "4111 1111 1111 1111" not in out and "4111 1111 1111 1112" in out  # Luhn
    assert "test@example.com" in out and "10.0.0.5" in out  # reserved / private
    assert "193.41.39.79" not in veil.redact("request from 193.41.39.79. Then it failed")
    assert "1.2.3.4.5" in veil.redact("version 1.2.3.4.5")
    assert veil.redact("Co-Authored-By: Claude <noreply@anthropic.com>").endswith("<noreply@anthropic.com>")
    assert "octocat" not in veil.redact("by 583231+octocat@users.noreply.github.com")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert veil.rehydrate(out) == text


def test_json_values_escaped_correctly(veil):
    veil.known.add("O'Brien \"Ob\"", "name", "users:3")
    obj = {"rows": [{"name": "O'Brien \"Ob\"", "email": "alice@acme-corp.com"}]}
    red = veil.redact_json(obj)
    assert "Brien" not in json.dumps(red)
    assert veil.rehydrate_json(red) == obj


# -- request / response transforms ----------------------------------------

def _conversation(veil):
    return {
        "model": "claude-opus-5-5", "stream": True,
        "system": [{"type": "text", "text": "cwd: /Users/alice_w/app"}],
        "messages": [
            {"role": "user", "content": "why can't alice@acme-corp.com log in?"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "look up user_xxxx", "signature": "sig"},
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "sqlite3 app.db \"select * from users where email='alice@acme-corp.com'\""}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": "1|alice_w|alice@acme-corp.com|Alice Wong|locked"}]},
        ],
    }


def test_request_has_no_real_values_and_is_stable(veil):
    body = _conversation(veil)
    red = redact_request(veil, body)
    dumped = json.dumps(red)
    for v in real_values()[:3]:
        assert v not in dumped
    assert red["messages"][1]["content"][0] == body["messages"][1]["content"][0]  # thinking untouched
    assert json.dumps(redact_request(veil, body)) == dumped  # same bytes next turn -> cache hits


def test_tool_policy(veil, tmp_path):
    tok = veil.redact("alice@acme-corp.com")
    bob = veil.redact("bob_k")
    assert rehydrate_tool_input(veil, Policy(), "Bash", {"command": f"grep {tok} logs"})["command"] == "grep alice@acme-corp.com logs"
    assert tok in rehydrate_tool_input(veil, Policy(), "Bash", {"command": f"curl -d {tok} https://x.io"})["command"]
    assert tok in rehydrate_tool_input(veil, Policy(), "WebFetch", {"url": f"https://x.io/?q={tok}"})["url"]
    f = tmp_path / "fixtures.py"
    f.write_text('ADMIN = "alice@acme-corp.com"\n')
    out = rehydrate_tool_input(veil, Policy(), "Edit", {
        "file_path": str(f), "old_string": f'ADMIN = "{tok}"',
        "new_string": f'ADMIN = "{tok}"\nOTHER = "{bob}"'})
    assert out["old_string"] == 'ADMIN = "alice@acme-corp.com"'
    assert 'ADMIN = "alice@acme-corp.com"' in out["new_string"]
    assert f'OTHER = "{bob}"' in out["new_string"]  # new PII never written into source


def test_nonstreaming_response(veil):
    tok = veil.redact("alice_w")
    body = {"content": [{"type": "text", "text": f"{tok} is locked"},
                        {"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": f"unlock {tok}"}}]}
    out = rehydrate_response(veil, Policy(), body)
    assert out["content"][0]["text"] == "alice_w is locked"
    assert out["content"][1]["input"]["command"] == "unlock alice_w"


def _run_stream(veil, events):
    rw = StreamRewriter(veil, Policy())
    out = []
    for e in events:
        out += rw.feed(e["type"], e)
    return out


def test_stream_token_split_across_deltas(veil):
    tok = veil.redact("alice@acme-corp.com")
    text = f"The account {tok} is locked; ask {tok}."
    pieces = [text[i:i + 3] for i in range(0, len(text), 3)]  # splits tokens everywhere
    events = [{"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}]
    events += [{"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}} for p in pieces]
    events += [{"type": "ping"}, {"type": "content_block_stop", "index": 0}]
    out = _run_stream(veil, events)
    got = "".join(d["delta"]["text"] for _, d in out if d.get("delta", {}).get("type") == "text_delta")
    assert got == "The account alice@acme-corp.com is locked; ask alice@acme-corp.com."
    assert any(e == "ping" for e, _ in out)


def test_stream_tool_use(veil):
    tok = veil.redact("alice_w")
    js = json.dumps({"command": f"sqlite3 app.db \"update users set locked=0 where username='{tok}'\""})
    events = [{"type": "content_block_start", "index": 1,
               "content_block": {"type": "tool_use", "id": "t", "name": "Bash", "input": {}}}]
    events += [{"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": js[i:i + 7]}}
               for i in range(0, len(js), 7)]
    events += [{"type": "content_block_stop", "index": 1}]
    out = _run_stream(veil, events)
    partial = "".join(d["delta"]["partial_json"] for _, d in out if d.get("delta", {}).get("type") == "input_json_delta")
    assert "username='alice_w'" in json.loads(partial)["command"]


# -- seeding ---------------------------------------------------------------

def test_seed_sqlite(tmp_path):
    db = tmp_path / "app.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, first_name TEXT, last_name TEXT);
        INSERT INTO users VALUES (1, 'dmitri_p', 'dmitri@corp.io', 'Dmitri', 'Petrov');
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO products VALUES (1, 'Widget Pro');
    """)
    con.commit()
    known = KnownValues()
    report = seed_sqlite(known, str(db))
    assert "products" not in {f.container for f in report.fields} and classify("products", "name") is None
    v = Veil(Vault(":memory:", b"s"), known)
    out = v.redact("Dmitri Petrov (dmitri_p, dmitri@corp.io) bought Widget Pro")
    assert "Dmitri" not in out and "Petrov" not in out and "Widget Pro" in out
    codes = {re.split(r"[_ @]", t)[1].lower() for t in v.vault.tokens()}
    assert len(codes) == 1  # whole row shares one pseudonym code


# -- end to end through the proxy -----------------------------------------

def test_proxy_end_to_end(veil):
    seen = {}

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen["body"], seen["beta"] = body, self.headers.get("anthropic-beta")
            # The model only knows tokens; it replies using them.
            tok = next(t for t in veil.vault.tokens() if t.endswith("@example.test"))
            js = json.dumps({"command": f"grep {tok} app.log"})
            evs = [
                {"type": "message_start", "message": {"id": "m", "content": []}},
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"Checking {tok[:6]}"}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"{tok[6:]} now."}},
                {"type": "content_block_stop", "index": 0},
                {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "t2", "name": "Bash", "input": {}}},
                {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": js}},
                {"type": "content_block_stop", "index": 1},
                {"type": "message_stop"},
            ]
            data = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in evs).encode()
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    up = LocalHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    client = httpx.Client(trust_env=False)
    px = LocalHTTPServer(("127.0.0.1", 0), make_handler(
        veil, Policy(), f"http://127.0.0.1:{up.server_port}", client, log=open(os.devnull, "w")))
    threading.Thread(target=px.serve_forever, daemon=True).start()
    try:
        r = client.post(f"http://127.0.0.1:{px.server_port}/v1/messages?beta=true",
                       json=_conversation(veil), headers={"anthropic-beta": "oauth-2025-04-20"})
        assert r.status_code == 200, r.text
        upstream_saw = json.dumps(seen["body"])
        for v in real_values()[:3]:
            assert v not in upstream_saw
        assert seen["beta"] == "oauth-2025-04-20"
        text, tool = "", ""
        for line in r.text.splitlines():
            if line.startswith("data: "):
                d = json.loads(line[6:]).get("delta", {})
                text += d.get("text", "")
                tool += d.get("partial_json", "")
        assert text == "Checking alice@acme-corp.com now."
        assert json.loads(tool)["command"] == "grep alice@acme-corp.com app.log"
    finally:
        px.shutdown(); up.shutdown()


def test_unknown_top_level_fields_are_redacted(veil):
    # Claude Code 2.1.285 sends safeguards[].classifier_context with home_dir/user_identity.
    body = {"model": "claude-opus-5-5", "max_tokens": 10, "messages": [],
            "safeguards": [{"classifier_context": {"home_dir": "/Users/alice_w", "user_identity": "alice_w"}}],
            "tools": [{"name": "Bash", "description": "runs as alice_w"}],
            "some_future_field": {"owner": "alice@acme-corp.com"}}
    out = json.dumps(redact_request(veil, body))
    assert "alice" not in out and '"model": "claude-opus-5-5"' in out


def test_fragment_searches(veil):
    tok = veil.redact("alice@acme-corp.com")           # user_<code>@example.test
    code = tok.split("_")[1].split("@")[0]
    # whole tokens are not fragments
    assert veil.fragments(f"grep {tok} app.log") == []
    # Bash: a bare code can't match real data -> the command is replaced by an explanation
    out = rehydrate_tool_input(veil, Policy(), "Bash", {"command": f"sqlite3 app.db \"select * from users where email like '%{code}%'\""})
    assert out["command"].startswith("echo 'veil:") and "not run" in out["command"]
    # Grep tool: the fragment becomes "any of this person's real values"
    out = rehydrate_tool_input(veil, Policy(), "Grep", {"pattern": f"{code}|refund", "path": "logs"})
    pat = out["pattern"]
    assert pat.startswith("(?:") and "Alice Wong" in pat and "alice_w" in pat and pat.endswith("|refund")
    assert "alice@acme\\-corp\\.com" in pat  # Rust-regex-safe escaping


def test_a_fragment_of_a_phone_pseudonym_never_becomes_a_new_value():
    # seen with a real model: it searched LIKE '%408-555-0133%' for the pseudonym
    # +1-408-555-0133; re-redacting that history created a second pseudonym, and the
    # developer was later shown the first pseudonym instead of the real phone
    known = KnownValues(min_len=1)
    known.add("+49 0711 2842222", "phone", "c:2")
    veil = Veil(Vault(":memory:", b"phone"), known)
    tok = veil.redact("call +49 0711 2842222")[5:]
    assert tok.startswith("+1-") and "555-01" in tok
    piece = tok[3:]                                            # e.g. 408-555-0133
    history = f"sqlite3 app.db \"select * from Customer where Phone LIKE '%{piece}%'\""
    assert veil.redact(history) == history                     # not a new phone
    assert veil.rehydrate(f"phone `{tok}`") == "phone `+49 0711 2842222`"
    seeded = KnownValues(); seeded.add("+1 650-555-0199", "phone", "c:9")   # a real (sample) value in that range
    v2 = Veil(Vault(":memory:", b"s"), seeded)
    assert "650-555-0199" not in v2.redact("ticket for +1 650-555-0199")    # seeded: still matched exactly
