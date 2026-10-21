import base64
import json

import pytest

import veil.anthropic as anth
from veil.anthropic import redact_request
from veil.detect import KnownValues
from veil.engine import Veil
from veil.guard import Guard
from veil.vault import Vault


@pytest.fixture
def veil():
    known = KnownValues()
    known.add("leonekohler@surfeu.de", "email", "c:2")
    known.add("Leonie Köhler", "name", "c:2")
    return Veil(Vault(":memory:", b"g"), known)


def test_encoded_forms_are_redacted_by_main_pass(veil):
    text = ("GET /api/users?email=leonekohler%40surfeu.de\n"
            '{"name": "Leonie K\\u00f6hler"}\n'
            "file: Leonie Köhler.pdf\n"        # NFD, as macOS filenames are
            "From: LEONEKOHLER@SURFEU.DE".replace("LEONEKOHLER@SURFEU.DE", "leonekohler@surfeu.de".upper()))
    out = veil.redact(text)
    assert "surfeu" not in out.lower() and "hler" not in out
    email_tok = veil.redact("leonekohler@surfeu.de")
    assert out.count(email_tok) == 2  # URL-encoded form maps to the same token


def test_guard_repairs_field_the_redactor_skipped(veil, monkeypatch):
    monkeypatch.setattr(anth, "CONFIG_FIELDS", anth.CONFIG_FIELDS | {"safeguards"})  # simulate a coverage bug
    body = redact_request(veil, {"model": "m", "messages": [],
                                 "safeguards": [{"ctx": {"who": "leonekohler@surfeu.de"}}]})
    assert "leonekohler" in json.dumps(body)
    fixed, findings = Guard(veil).enforce(body)
    assert "leonekohler" not in json.dumps(fixed)
    assert [(f.path, f.form, f.repaired) for f in findings] == [("safeguards[0].ctx.who", "plain", True)]


def test_guard_catches_base64(veil):
    blob = base64.b64encode(b'{"user": {"email": "leonekohler@surfeu.de", "id": 2}}').decode()
    body = redact_request(veil, {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": f"session cookie: {blob}"}]}]})
    fixed, findings = Guard(veil).enforce(body)
    assert any(f.form == "base64" and f.repaired for f in findings)
    assert "[veil:base64-redacted]" in json.dumps(fixed)


def test_guard_reports_but_allows_real_values_in_model_thinking(veil):
    body = {"messages": [{"role": "assistant", "content": [
        {"type": "thinking", "thinking": "the user is leonekohler@surfeu.de", "signature": "sig"}]}]}
    fixed, findings = Guard(veil).enforce(redact_request(veil, body))
    assert findings and all(f.allowed and not f.repaired for f in findings)
    assert fixed["messages"][0]["content"][0]["thinking"] == "the user is leonekohler@surfeu.de"  # signed: untouched


def test_guard_withholds_escaped_dumps(veil):
    # what `sed -n l app.log` printed in a real DeepSeek session: wrapped + octal-escaped
    dump = 'customer="Leonie K\\303\\266hler" email=leonekoh\\\nler@surfeu.de$\n'
    body = redact_request(veil, {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": dump}]}]})
    fixed, findings = Guard(veil).enforce(body)
    assert any(f.form in ("escaped", "transformed") and f.repaired for f in findings)
    out = fixed["messages"][0]["content"][0]["content"]
    assert out.startswith("[veil: output withheld") and "hler" not in out


def test_byte_dump_commands_are_not_run(veil):
    from veil.anthropic import Policy, rehydrate_tool_input
    for cmd in ["sed -n l app.log", "sed -n '1,40l' app.log", "od -c app.log", "xxd app.log", "cat -A app.log"]:
        assert rehydrate_tool_input(veil, Policy(), "Bash", {"command": cmd})["command"].startswith("echo 'veil:")
    assert rehydrate_tool_input(veil, Policy(), "Bash", {"command": "sed -n '1,40p' app.log"})["command"] == \
        "sed -n '1,40p' app.log"


def test_guard_quiet_on_clean_traffic(veil):
    body = redact_request(veil, {"system": "You are helpful. Commit as Claude <noreply@anthropic.com>.",
                                 "messages": [{"role": "user", "content": "Leonie Köhler (leonekohler@surfeu.de) "
                                                                          "pinged from 10.0.0.4 about v2.1.285"}]})
    _, findings = Guard(veil).enforce(body)
    assert findings == []


class FakeNer:
    """Stands in for GLiNER: tags 'Claude Code' (a classic false positive) as a person."""
    def find(self, text):
        from veil.detect import Span
        i = text.find("Claude Code")
        return [Span(i, i + 11, "name", "Claude Code", None, priority=-1)] if i >= 0 else []


def test_ner_guesses_never_become_guard_needles(veil):
    veil.ner = FakeNer()
    body = {"model": "m", "system": "You are Claude Code, a CLI.",
            "messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                                       "content": "built with Claude Code"}]}]}
    red = redact_request(veil, body)  # NER runs on the tool result only
    assert "Claude Code" not in json.dumps(red["messages"])
    fixed, findings = Guard(veil).enforce(red)
    assert fixed["system"] == "You are Claude Code, a CLI." and findings == []


def test_full_name_token_composes_from_parts():
    from veil.detect import KnownValues
    known = KnownValues()
    known.add("Leonie", "first_name", "c:2"); known.add("Köhler", "last_name", "c:2")
    known.add("Leonie Köhler", "name", "c:2")
    v = Veil(Vault(":memory:", b"g"), known)
    assert v.redact("Leonie Köhler") == v.redact("Leonie") + " " + v.redact("Köhler")


def test_schema_property_named_type_does_not_crash(veil):
    # Claude Code tool schemas can contain {"properties": {"type": {"type": "string"}}}
    body = {"model": "m", "tools": [{"name": "Write", "input_schema": {"type": "object", "properties": {
        "type": {"type": "string", "enum": ["file", "dir"]}, "path": {"type": "string"}}}}],
            "messages": [{"role": "user", "content": "hi leonekohler@surfeu.de"}]}
    fixed, findings = Guard(veil).enforce(redact_request(veil, body))
    assert fixed["tools"][0]["input_schema"]["properties"]["type"] == {"type": "string", "enum": ["file", "dir"]}


def test_word_gluing_does_not_trigger_on_common_phrases():
    """Found in the pilot: with ~40k seeded values, whitespace-stripping turned 'retry logic
    matches on wording' into '...atcheson...' (a seeded surname) and would have withheld it."""
    from veil.detect import KnownValues
    known = KnownValues()
    known.add("Atcheson", "last_name", "u:1"); known.add("Messager", "last_name", "u:2")
    v = Veil(Vault(":memory:", b"g"), known)
    text = "Claude Code's retry logic matches on wording; the message request failed"
    body = redact_request(v, {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": text}]}]})
    fixed, findings = Guard(v).enforce(body)
    assert findings == [] and fixed["messages"][0]["content"][0]["content"] == text
