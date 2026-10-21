"""OpenAI Chat Completions adapter."""

import json

import pytest

from veil.anthropic import Policy
from veil.detect import KnownValues
from veil.engine import Veil
from veil.openai import ChatStreamRewriter, redact_chat_request, rehydrate_args, rehydrate_chat_response
from veil.vault import Vault


@pytest.fixture
def veil():
    k = KnownValues()
    k.add("leonekohler@surfeu.de", "email", "c:2"); k.add("Leonie Köhler", "name", "c:2")
    return Veil(Vault(":memory:", b"s"), k)


def test_request_redaction_covers_every_channel(veil):
    body = {"model": "deepseek-flash", "stream": True, "user": "leonekohler@surfeu.de",
            "tools": [{"type": "function", "function": {"name": "shell", "description": "run",
                                                         "parameters": {"type": "object"}}}],
            "messages": [
                {"role": "system", "content": "You are an agent."},
                {"role": "user", "content": [{"type": "text", "text": "why did Leonie Köhler get charged twice?"}]},
                {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
                    "name": "shell", "arguments": json.dumps({"command": "grep leonekohler@surfeu.de app.log"})}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "dup charge for leonekohler@surfeu.de"}]}
    out = redact_chat_request(veil, body, notice=True)
    dumped = json.dumps(out, ensure_ascii=False)
    assert "leonekohler" not in dumped and "Köhler" not in dumped
    assert out["model"] == "deepseek-flash"
    assert out["messages"][1]["role"] == "system" and "pseudonyms" in out["messages"][1]["content"]  # after system
    assert json.loads(out["messages"][3]["tool_calls"][0]["function"]["arguments"])["command"].startswith("grep user_")
    assert json.dumps(redact_chat_request(veil, body, notice=True)) == json.dumps(out)  # deterministic -> caching


def test_tool_argument_shapes(veil):
    tok = veil.redact("leonekohler@surfeu.de")
    p = Policy()
    assert json.loads(rehydrate_args(veil, p, "shell", json.dumps({"command": f"grep {tok} log"})))["command"] \
        == "grep leonekohler@surfeu.de log"
    argv = json.loads(rehydrate_args(veil, p, "exec_command", json.dumps({"cmd": ["bash", "-lc", f"grep '{tok}' log"]})))
    assert argv["cmd"] == ["bash", "-lc", "grep 'leonekohler@surfeu.de' log"]
    plain = json.loads(rehydrate_args(veil, p, "shell", json.dumps({"command": ["grep", tok, "log"]})))
    assert plain["command"] == ["grep", "leonekohler@surfeu.de", "log"]
    egress = json.loads(rehydrate_args(veil, p, "run_terminal_cmd", json.dumps({"command": f"curl -d {tok} x.io"})))
    assert tok in egress["command"]
    assert tok in rehydrate_args(veil, p, "send_slack_message", json.dumps({"text": tok}))  # unknown sink
    dump = json.loads(rehydrate_args(veil, p, "shell", json.dumps({"command": ["xxd", "app.log"]})))
    assert dump["command"][-1].startswith("echo 'veil:")


def test_nonstream_response(veil):
    tok = veil.redact("leonekohler@surfeu.de")
    body = {"choices": [{"index": 0, "message": {"role": "assistant", "content": f"{tok} was charged twice",
                                                 "tool_calls": [{"id": "c", "type": "function", "function": {
                                                     "name": "shell", "arguments": json.dumps({"command": f"grep {tok} x"})}}]}}]}
    out = rehydrate_chat_response(veil, Policy(), body)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "leonekohler@surfeu.de was charged twice"
    assert "leonekohler@surfeu.de" in msg["tool_calls"][0]["function"]["arguments"]


def test_stream_text_split_and_tool_call_deltas(veil):
    tok = veil.redact("leonekohler@surfeu.de")
    text = f"Customer {tok} paid twice."
    args = json.dumps({"command": f"grep {tok} app.log"})
    chunks = [{"id": "x", "choices": [{"index": 0, "delta": {"role": "assistant", "content": text[i:i + 4]}}]}
              for i in range(0, len(text), 4)]
    chunks += [{"id": "x", "choices": [{"index": 0, "delta": {"tool_calls": [
        {"index": 0, "id": "c1" if i == 0 else None, "type": "function",
         "function": {"name": "shell" if i == 0 else None, "arguments": args[i:i + 6]}}]}}]} for i in range(0, len(args), 6)]
    chunks += [{"id": "x", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
               {"id": "x", "choices": [], "usage": {"prompt_tokens": 10}}]
    rw = ChatStreamRewriter(veil, Policy())
    out = [c for ch in chunks for c in rw.feed(ch)]
    got_text = "".join(d["delta"].get("content") or "" for c in out for d in c["choices"])
    assert got_text == "Customer leonekohler@surfeu.de paid twice."
    calls = [tc for c in out for d in c["choices"] for tc in d["delta"].get("tool_calls", [])]
    assert len(calls) == 1 and json.loads(calls[0]["function"]["arguments"])["command"] == "grep leonekohler@surfeu.de app.log"
    assert rw.view["content"][0]["text"] == text  # the model's own (tokenised) view is kept for audits
