"""Team mode: identical pseudonyms across machines; managed-settings drop-in."""

import base64
import json

import pytest

from veil import cli, state, team
from veil.detect import set_allowlist

REAL = ["leonekohler@surfeu.de", "Leonie Köhler", "Theodor-Heuss-Straße 34"]


def machine(monkeypatch, home, vault_key):
    monkeypatch.setenv("VEIL_HOME", str(home))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(vault_key).decode())  # each machine: own vault key
    monkeypatch.delenv("VEIL_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("VEIL_KEYCHAIN", str(home / "absent.keychain-db"))  # never touch a real keychain
    v = state.load()
    for value, kind in zip(REAL, ("email", "name", "address")):
        v.known.add(value, kind, "c:2")
    return v


def test_teammates_derive_identical_pseudonyms(tmp_path, monkeypatch, capsys):
    a = machine(monkeypatch, tmp_path / "a", b"A" * 32)
    tokens_a = a.redact(" | ".join(REAL))
    monkeypatch.setenv("TEAM_PW", "correct horse battery staple")
    cli.main(["team", "allow", "support@shop.example.org"])
    cli.main(["team", "export", "--passphrase-env", "TEAM_PW"])
    bundle = capsys.readouterr().out.strip()
    assert bundle.startswith("veil-team-v1:") and "leonekohler" not in bundle
    with pytest.raises(Exception):
        team.import_bundle(bundle, "wrong passphrase")

    b = machine(monkeypatch, tmp_path / "b", b"B" * 32)
    b.redact("someone@else.org")  # B already has a token from its own secret
    with pytest.raises(SystemExit):
        cli.main(["team", "join", bundle, "--passphrase-env", "TEAM_PW"])  # refuses to mix secrets
    cli.main(["team", "join", bundle, "--passphrase-env", "TEAM_PW", "--reset-vault"])
    b2 = machine(monkeypatch, tmp_path / "b", b"B" * 32)  # reload with the team secret
    assert b2.redact(" | ".join(REAL)) == tokens_a
    assert b2.redact("mail support@shop.example.org") == "mail support@shop.example.org"  # team allowlist
    set_allowlist([])


def test_managed_settings_dropin(tmp_path):
    doc = team.managed_settings(8787, hooks=True, lock_hooks=True)
    assert doc["allowedProviders"] == ["customEndpoint"]
    assert doc["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8787"
    assert doc["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "veil-hook post --port 8787"
    assert doc["allowManagedHooksOnly"] is True
    assert "managed-settings.d" in team.install_hint(str(tmp_path / "50-veil.json"))
    assert "allowManagedHooksOnly" not in team.managed_settings(8787)
