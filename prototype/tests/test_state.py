"""At-rest encryption of the local vault and seed dictionary."""

import base64
import json
import os
import sqlite3
import subprocess
import sys

import pytest

REAL = ["leonekohler@surfeu.de", "Leonie Köhler", "Theodor-Heuss-Straße 34"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    return tmp_path


def _plaintext_in(path, values):
    raw = open(path, "rb").read()
    return [v for v in values if v.encode() in raw]


def test_values_encrypted_at_rest_and_reload(home):
    from veil import state
    veil = state.load()
    veil.known.add(REAL[0], "email", "c:2"); veil.known.add(REAL[1], "name", "c:2"); veil.known.add(REAL[2], "address", "c:2")
    out = veil.redact(" | ".join(REAL))
    state.save_known(veil.known, veil.vault.cipher)
    veil.vault._db.close()
    assert _plaintext_in(home / "vault.db", REAL) == []
    assert _plaintext_in(home / "known.enc", REAL) == []
    again = state.load()
    assert again.redact(" | ".join(REAL)) == out and again.rehydrate(out) == " | ".join(REAL)


def test_v1_plaintext_state_is_migrated(home, monkeypatch):
    # a v1 home: plaintext vault table, known.json, token secret in a file
    db = sqlite3.connect(home / "vault.db")
    db.execute("CREATE TABLE entities (kind TEXT, value TEXT, token TEXT UNIQUE, grp TEXT, PRIMARY KEY (kind, value))")
    db.execute("INSERT INTO entities VALUES ('email', ?, 'user_ab12@example.test', 'c:2')", (REAL[0],))
    db.commit(); db.close()
    (home / "known.json").write_text(json.dumps([[REAL[1], "name", "c:2"]]))
    (home / "secret").write_bytes(b"s" * 32)
    monkeypatch.delenv("VEIL_TOKEN_SECRET")  # take the legacy file instead
    monkeypatch.setenv("VEIL_KEYCHAIN", str(home / "absent.keychain-db"))  # never touch a real keychain
    from veil import state
    veil = state.load()
    assert veil.redact(REAL[0]) == "user_ab12@example.test"  # existing token kept
    assert veil.rehydrate("user_ab12@example.test") == REAL[0]
    veil.vault._db.close()
    assert not (home / "known.json").exists() and not (home / "secret").exists()
    assert _plaintext_in(home / "vault.db", REAL) == []  # incl. freed pages (VACUUM)


def test_tampering_and_wrong_key_fail(home, monkeypatch):
    from cryptography.exceptions import InvalidTag
    from veil import state
    veil = state.load()
    veil.known.add(REAL[0], "email", "a"); veil.known.add("someone.else@mail.org", "email", "b")
    veil.redact(f"{REAL[0]} someone.else@mail.org")
    veil.vault._db.close()
    db = sqlite3.connect(home / "vault.db")
    (t1, v1), (t2, v2) = db.execute("SELECT token, value FROM entities_v2").fetchall()
    db.execute("UPDATE entities_v2 SET value = ? WHERE token = ?", (v2, t1))  # swap ciphertexts
    db.execute("UPDATE entities_v2 SET value = ? WHERE token = ?", (v1, t2))
    db.commit(); db.close()
    with pytest.raises(InvalidTag):
        state.load()
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"w" * 32).decode())
    with pytest.raises(InvalidTag):
        state.load()


@pytest.mark.skipif(sys.platform != "darwin" or not os.environ.get("VEIL_TEST_KEYCHAIN"),
                    reason="opt-in: VEIL_TEST_KEYCHAIN=1 (creates and deletes a throwaway keychain file)")
def test_macos_keychain(tmp_path, monkeypatch):
    kc = str(tmp_path / "veil-test.keychain-db")
    subprocess.run(["security", "create-keychain", "-p", "pw", kc], check=True)
    try:
        subprocess.run(["security", "unlock-keychain", "-p", "pw", kc], check=True)
        monkeypatch.setenv("VEIL_KEYCHAIN", kc)
        monkeypatch.delenv("VEIL_VAULT_KEY", raising=False)
        from veil.keys import get_key
        k1 = get_key("vault-key", str(tmp_path))
        k2 = get_key("vault-key", str(tmp_path))
        assert k1 == k2 and len(k1) == 32
        assert not (tmp_path / "keys").exists()  # stored in the keychain, not a file
    finally:
        subprocess.run(["security", "delete-keychain", kc], check=False)


def test_two_processes_share_one_vault(home):
    """A hook process and the long-running proxy use the same vault file."""
    from veil import state
    proxy, hook = state.load(), state.load()   # two independent connections, like two processes
    for v in (proxy, hook):
        v.known.add(REAL[0], "email", "c:2")
    t_hook = hook.redact("card 4111 1111 1111 1111 for " + REAL[0])   # hook allocates new tokens
    assert proxy.rehydrate(t_hook) == "card 4111 1111 1111 1111 for " + REAL[0]  # proxy sees them
    assert proxy.redact(REAL[0]) == hook.redact(REAL[0])                      # same token everywhere


def test_absent_keychain_never_falls_back_to_login_keychain(tmp_path, monkeypatch):
    """Regression: an explicit-but-missing VEIL_KEYCHAIN once made `security -i` write
    to the default (login) keychain while veil fell back to a key file."""
    from veil import keys
    monkeypatch.setenv("VEIL_KEYCHAIN", str(tmp_path / "absent.keychain-db"))
    calls = []
    monkeypatch.setattr(keys.subprocess, "run", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError))
    assert keys._keychain_get("token-secret") is None and keys._keychain_put("token-secret", b"x" * 32) is False
    assert calls == []  # the `security` tool was never invoked
