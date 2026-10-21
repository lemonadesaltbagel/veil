"""Quasi-identifiers (city, postal code, birth date, company, job title) and direct
identifiers (SSN, IBAN, passport...)."""

import base64
import io
import json
import os

import httpx
import pytest

from veil import cli, state
from veil.detect import KnownValues, detect
from veil.engine import Veil
from veil.quasi import Monitor
from veil.sources import seed
from veil.sources.core import Container, plan
from veil.vault import Vault
from veil_dev.testing import Recorder, start_mock_llm, start_proxy

HERE = os.path.dirname(__file__)
CHINOOK = os.path.join(HERE, "..", "datasets", "chinook.sqlite")


def _known():
    k = KnownValues()
    k.add("leonekohler@surfeu.de", "email", "c:2")
    k.add_quasi("Stuttgart", "city", "c:2")          # rare: one person
    k.add_quasi("1978-03-02 00:00:00", "dob", "c:2")  # time part dropped
    k.add_quasi("70174", "postal_code", "c:2")
    for i in range(6):
        k.add_quasi("London", "city", f"c:{10 + i}")  # shared by six: not identifying
    k.add_quasi("Mobile", "city", "c:3")               # a dictionary word: never a needle
    return k


def test_only_rare_values_count():
    k = _known()
    assert set(k.rare_quasi()) == {"Stuttgart", "1978-03-02", "70174"}
    spans = k.find_quasi("moved from London to Stuttgart (70174), born 1978-03-02, Mobile app")
    assert sorted((s.kind, s.value) for s in spans) == [("city", "Stuttgart"), ("dob", "1978-03-02"),
                                                        ("postal_code", "70174")]


def test_planned_only_on_person_records():
    people = Container("customers", "id", {"email": {}, "city": {}, "company": {}, "title": {}},
                       [{"email": f"u{i}@x.org", "city": "Oslo", "company": "Acme", "title": "CTO"} for i in range(5)])
    posts = Container("posts", "id", {"title": {}, "city": {}}, [{"title": "Hello", "city": "Oslo"}])
    assert sorted(f.kind for f in plan(people) if f.kind.startswith("qi:")) == ["qi:city", "qi:company", "qi:job_title"]
    assert [f for f in plan(posts) if f.kind.startswith("qi:")] == []


@pytest.mark.skipif(not os.path.exists(CHINOOK), reason="datasets not downloaded")
def test_chinook_quasi_columns_including_birth_dates():
    k = KnownValues()
    report = seed(k, CHINOOK)
    kinds = {(f.container, f.path, f.kind) for f in report.fields if f.kind.startswith("qi:")}
    assert ("Employee", "BirthDate", "qi:dob") in kinds and ("Customer", "Company", "qi:company") in kinds
    assert "1962-02-18" in k.rare_quasi()                     # a DATETIME column, read as a date
    assert "Calgary" not in k.rare_quasi()                    # shared by many records


def test_redact_mode_pseudonymises_without_linking_people():
    veil = Veil(Vault(":memory:", b"q"), _known())
    text = "Leonie (leonekohler@surfeu.de) lives in Stuttgart 70174, born 1978-03-02; office in London"
    assert veil.redact(text).count("Stuttgart") == 1          # warn (default): unchanged
    veil.quasi_mode = "redact"
    out = veil.redact(text)
    assert "Stuttgart" not in out and "70174" not in out and "1978-03-02" not in out and "London" in out
    city_tok = veil.vault.token_for("city", "Stuttgart")
    assert city_tok.startswith("city_") and city_tok[5:] not in veil.redact("leonekohler@surfeu.de")
    assert veil.rehydrate(out) == text


def test_monitor_reports_kinds_once_and_never_values():
    k, m = _known(), Monitor()
    line = m.check(k, ["Leonie lives in Stuttgart 70174, born 1978-03-02"])
    assert "city x1" in line and "dob x1" in line and "postal_code x1" in line and "2+ kinds" in line
    assert not any(v in line for v in ("Stuttgart", "70174", "1978"))
    assert m.check(k, ["again: Stuttgart 70174"]) is None    # history repeats every request


def test_direct_identifiers():
    found = lambda t: [(s.kind, s.value) for s in detect(t, None, lambda x: False)]
    assert found("ssn 123-45-6789, iban DE89 3704 0044 0532 0130 00") == [
        ("id_number", "123-45-6789"), ("id_number", "DE89 3704 0044 0532 0130 00")]
    assert found("order 666-12-3456 and DE89 3704 0044 0532 0130 01") == []  # invalid SSN range, bad checksum
    people = Container("users", "id", {"email": {}, "passport_no": {}, "tax_id": {}},
                       [{"email": "a@b.org", "passport_no": "X1234567", "tax_id": "12/345/67890"}])
    assert {f.path: f.kind for f in plan(people)}["passport_no"] == "id_number"


def test_proxy_warns_and_cli_switches(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    monkeypatch.delenv("VEIL_QUASI", raising=False)
    veil = Veil(Vault(":memory:", b"s"), _known())
    log, rec, llm = io.StringIO(), Recorder(), start_mock_llm()
    px = start_proxy(veil, f"http://127.0.0.1:{llm.server_port}", rec, log=log)
    url = f"http://127.0.0.1:{px.server_port}/v1/messages"
    body = {"model": "m", "max_tokens": 20, "messages": [{"role": "user", "content": "customer in Stuttgart, 70174"}]}
    try:
        with httpx.Client(trust_env=False) as c:
            c.post(url, json=body)
            assert "quasi-identifiers reached the model: city x1, postal_code x1" in log.getvalue()
            assert "Stuttgart" in json.dumps(rec.exchanges[-1]["sent"])   # warn leaves values
            cli.main(["quasi", "redact"])
            assert "quasi-identifiers: redact" in capsys.readouterr().out
            c.post(url, json=body)
            assert "Stuttgart" not in json.dumps(rec.exchanges[-1]["sent"])
            health = c.get(url.replace("/v1/messages", "/veil/health")).json()
            assert health["quasi"] == "redact" and health["quasi_reported"] == 2
    finally:
        px.shutdown(); llm.shutdown()
    assert "Stuttgart" not in log.getvalue() and "70174" not in log.getvalue()
