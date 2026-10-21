"""OpenAI Responses API adapter (Codex)."""

import json

import pytest

from veil.anthropic import Policy
from veil.detect import KnownValues
from veil.engine import Veil
from veil.responses import ItemRehydrator, ResponsesStreamRewriter, redact_responses_request
from veil_dev.testing import _responses_sse
from veil.vault import Vault

REAL = {"leonekohler@surfeu.de": "email", "Leonie Köhler": "name", "Theodor-Heuss-Straße 34": "address"}


@pytest.fixture
def veil():
    k = KnownValues()
    for v, kind in REAL.items():
        k.add(v, kind, "c:2")
    return Veil(Vault(":memory:", b"s"), k)


def test_request_items(veil):
    body = {"model": "gpt-6", "stream": True, "prompt_cache_key": "abc", "instructions": "Agent for Leonie Köhler",
            "client_metadata": {"owner": "leonekohler@surfeu.de"},
            "tools": [{"type": "function", "name": "exec_command", "parameters": {"type": "object"}}],
            "input": [
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "rules"}]},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "check leonekohler@surfeu.de"}]},
                {"type": "reasoning", "id": "rs_1", "encrypted_content": "gAAAAB...", "summary": []},
                {"type": "function_call", "call_id": "c1", "name": "exec_command",
                 "arguments": json.dumps({"cmd": "grep leonekohler@surfeu.de app.log"})},
                {"type": "function_call_output", "call_id": "c1", "output": "dup for Leonie Köhler"}]}
    out = redact_responses_request(veil, body, notice=True)
    dumped = json.dumps(out, ensure_ascii=False)
    assert all(v not in dumped for v in REAL)
    assert out["prompt_cache_key"] == "abc" and out["model"] == "gpt-6"
    assert out["input"][1]["role"] == "developer" and "pseudonyms" in out["input"][1]["content"][0]["text"]
    assert out["input"][3] == body["input"][2]  # reasoning untouched


def test_tool_sinks(veil, tmp_path):
    tok = veil.redact("leonekohler@surfeu.de")
    ir = ItemRehydrator(veil, Policy())
    fc = ir.item({"type": "function_call", "id": "f1", "name": "exec_command", "arguments": json.dumps({"cmd": f"grep '{tok}' x"})})
    assert json.loads(fc["arguments"])["cmd"] == "grep 'leonekohler@surfeu.de' x"
    stdin = ir.item({"type": "function_call", "id": "f2", "name": "write_stdin", "arguments": json.dumps({"chars": tok})})
    assert tok in stdin["arguments"]  # keystrokes into a (maybe shell) session: no real values
    f = tmp_path / "fixtures.py"
    f.write_text('OWNER = "leonekohler@surfeu.de"\n')
    other = veil.redact("Leonie Köhler")
    patch = (f"*** Begin Patch\n*** Update File: {f}\n@@\n-OWNER = \"{tok}\"\n+OWNER = \"{tok}\"\n"
             f"+NAME = \"{other}\"\n*** End Patch")
    out = ir.item({"type": "custom_tool_call", "name": "apply_patch", "input": patch})["input"]
    assert 'OWNER = "leonekohler@surfeu.de"' in out and f'NAME = "{other}"' in out  # no new PII into code


def test_stream_consistency(veil):
    real = 'ok "Leonie Köhler" leonekohler@surfeu.de ship_to="Theodor-Heuss-Straße 34"'
    tok = veil.redact(real)
    raw = _responses_sse([{"type": "message", "text": tok},
                          {"type": "function_call", "name": "exec_command", "arguments": {"cmd": f"grep {veil.redact('leonekohler@surfeu.de')} log"}}],
                         "gpt-6", 1).decode()
    rw = ResponsesStreamRewriter(veil, Policy())
    deltas, args_delta, args_done, completed = "", "", None, None
    for frame in raw.strip().split("\n\n"):
        for ev in rw.feed(json.loads(frame.split("data: ", 1)[1])):
            if ev["type"] == "response.output_text.delta":
                deltas += ev["delta"]
            elif ev["type"] == "response.function_call_arguments.delta":
                args_delta += ev["delta"]
            elif ev["type"] == "response.function_call_arguments.done":
                args_done = ev["arguments"]
            elif ev["type"] == "response.completed":
                completed = ev["response"]["output"]
    assert deltas == real == completed[0]["content"][0]["text"]
    assert args_delta == args_done == completed[1]["arguments"]
    assert json.loads(args_done)["cmd"] == "grep leonekohler@surfeu.de log"
