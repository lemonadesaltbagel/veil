"""Key rotation: the vault key re-encrypts everything (pseudonyms unchanged, crash-safe);
the token secret issues new pseudonyms while old ones still rehydrate."""

import http.server
import os
import threading

from veil.proxy import LocalHTTPServer
import pytest
from cryptography.exceptions import InvalidTag

from veil import cli, rotate, state
from veil.crypto import Cipher
from veil.keys import peek_key, set_key


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_KEYCHAIN", str(tmp_path / "no-such.keychain"))  # file keys; never the login keychain
    monkeypatch.setenv("VEIL_SECRET_SERVICE", "0")
    for var in ("VEIL_VAULT_KEY", "VEIL_TOKEN_SECRET"):
        monkeypatch.delenv(var, raising=False)
    veil = state.load()
    veil.known.add("leonekohler@surfeu.de", "email", "c:2")
    state.save_known(veil.known, veil.vault.cipher)
    state.save_sources(["postgresql://app:pw@localhost/app"], veil.vault.cipher)
    tok = veil.redact("mail leonekohler@surfeu.de")
    return str(tmp_path), tok


def test_vault_key_rotation_keeps_pseudonyms(home):
    h, tok = home
    old = peek_key("vault-key", h)
    import sqlite3
    con = sqlite3.connect(os.path.join(h, "vault.db"))
    old_blobs = [b for (b,) in con.execute("SELECT value FROM entities_v2")]
    con.close()
    r = rotate.rotate_vault_key(h)
    raw = open(os.path.join(h, "vault.db"), "rb").read()
    assert old_blobs and not any(b in raw for b in old_blobs)   # no old-key ciphertext left in free pages
    assert r == {"vault_rows": 1, "retired": 0, "files": 2}
    new = peek_key("vault-key", h)
    assert new != old and peek_key("vault-key-next", h) is None
    veil = state.load()
    assert veil.redact("mail leonekohler@surfeu.de") == tok and len(veil.known) >= 1
    assert state.load_sources() == ["postgresql://app:pw@localhost/app"]
    with pytest.raises(InvalidTag):  # the old key opens nothing any more
        Cipher(old).open(open(os.path.join(h, "known.enc"), "rb").read(), "known")


def test_interrupted_rotation_is_finished_on_load(home):
    h, tok = home
    old, new = peek_key("vault-key", h), os.urandom(32)
    open(os.path.join(h, rotate.MARKER), "w").close()
    set_key("vault-key-next", h, new)
    rotate.reencrypt(h, [old], new)          # ... and the process died before switching keys
    veil = state.load()
    assert peek_key("vault-key", h) == new and peek_key("vault-key-next", h) is None
    assert not os.path.exists(os.path.join(h, rotate.MARKER))
    assert veil.redact("mail leonekohler@surfeu.de") == tok


def test_token_secret_rotation_retires_old_pseudonyms(home):
    h, tok = home
    rotate.rotate_token_secret(h, state.load().vault)
    veil = state.load()
    fresh = veil.redact("mail leonekohler@surfeu.de")
    assert fresh != tok                                        # new pseudonym from now on
    assert veil.rehydrate(tok) == "mail leonekohler@surfeu.de"  # in-flight conversations still work
    assert veil.rehydrate(fresh) == "mail leonekohler@surfeu.de"
    rotate.rotate_vault_key(h)                                 # retired rows are re-encrypted too
    assert state.load().rehydrate(tok) == "mail leonekohler@surfeu.de"
    rotate.rotate_token_secret(h, state.load().vault, drop_old=True)
    assert state.load().rehydrate(tok) == tok                  # forgotten


def test_cli_refuses_while_a_proxy_runs(home, capsys):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    srv = LocalHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(SystemExit, match="proxy is running"):
            cli.main(["keys", "rotate", "--port", str(srv.server_port)])
    finally:
        srv.shutdown()
    free = srv.server_port  # nothing listens there now
    assert cli.main(["keys", "rotate", "--port", str(free)]) == 0
    assert "pseudonyms unchanged" in capsys.readouterr().out
