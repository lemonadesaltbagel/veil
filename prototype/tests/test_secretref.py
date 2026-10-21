"""Team secrets through secrets managers: export --to, join --from, sync. Fakes: `op` and
`gcloud` CLIs on PATH, a Vault KV v2 HTTP server, an AWS Secrets Manager endpoint (JSON
protocol, real botocore client)."""

import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler

import pytest

from veil import cli, secretref, state
from veil.keys import get_key
from veil.proxy import LocalHTTPServer


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path / "home"))
    for v in ("VEIL_VAULT_KEY", "VEIL_TOKEN_SECRET"):
        monkeypatch.delenv(v, raising=False)
    return tmp_path


def _serve(handler):
    srv = LocalHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_vault_kv2_roundtrip(home, monkeypatch):
    store = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, code, obj=None):
            data = json.dumps(obj or {}).encode()
            self.send_response(code); self.send_header("content-length", str(len(data))); self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            assert self.headers["X-Vault-Token"] == "root-token"
            store[self.path] = json.loads(self.rfile.read(int(self.headers["content-length"])))["data"]
            self._reply(200)

        def do_GET(self):
            assert self.headers["X-Vault-Token"] == "root-token"
            self._reply(200, {"data": {"data": store[self.path]}}) if self.path in store else self._reply(404)
    srv = _serve(H)
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("VAULT_TOKEN", "root-token")
    try:
        secretref.write("vault://secret/veil/team#bundle", "B1")
        assert store == {"/v1/secret/data/veil/team": {"bundle": "B1"}}
        assert secretref.read("vault://secret/veil/team#bundle") == "B1"
    finally:
        srv.shutdown()


def test_aws_secrets_manager_roundtrip(home, monkeypatch):
    pytest.importorskip("botocore")
    store = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            op = self.headers["X-Amz-Target"].split(".")[1]
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            sid = body.get("SecretId") or body.get("Name")
            if op == "PutSecretValue" and sid not in store:
                out, code = {"__type": "ResourceNotFoundException", "message": "no"}, 400
            elif op in ("PutSecretValue", "CreateSecret"):
                store[sid] = body["SecretString"]; out, code = {"Name": sid}, 200
            else:
                out, code = {"SecretString": store[sid]}, 200
            data = json.dumps(out).encode()
            self.send_response(code); self.send_header("content-type", "application/x-amz-json-1.1")
            self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
    srv = _serve(H)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")
    ref = f"aws-sm://veil/team?region=eu-west-1&endpoint=http://127.0.0.1:{srv.server_port}"
    try:
        secretref.write(ref, "B2")            # not there yet: created
        secretref.write(ref, "B3")            # then a new value
        assert store == {"veil/team": "B3"} and secretref.read(ref) == "B3"
    finally:
        srv.shutdown()


@pytest.mark.skipif(sys.platform == "win32", reason="fake CLIs are shell scripts")
def test_op_and_gcloud_get_secrets_on_stdin_not_argv(home, monkeypatch):
    bin_dir, log = home / "bin", home / "argv.log"
    bin_dir.mkdir()
    for name in ("op", "gcloud"):
        (bin_dir / name).write_text(f'#!/bin/sh\necho "{name} $@" >> "{log}"\ncat > "{home}/{name}.stdin"\n'
                                    f'echo stored-value\n')
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    secretref.write("op://Engineering/veil-team/bundle", "SECRET-BUNDLE")
    secretref.write("gcp-sm://my-proj/veil-team", "SECRET-BUNDLE")
    assert "SECRET-BUNDLE" not in log.read_text()                                  # never in argv
    assert "SECRET-BUNDLE" in (home / "op.stdin").read_text() and (home / "gcloud.stdin").read_text() == "SECRET-BUNDLE"
    assert secretref.read("op://Engineering/veil-team/bundle") == "stored-value"


def test_join_from_and_sync_rotate_with_the_team(home, monkeypatch, capsys):
    bundle_file = home / "team.bundle"
    lead = {"VEIL_HOME": str(home / "lead"), "VEIL_TOKEN_SECRET": base64.b64encode(b"L" * 32).decode()}
    monkeypatch.setenv("VEIL_HOME", lead["VEIL_HOME"]); monkeypatch.setenv("VEIL_TOKEN_SECRET", lead["VEIL_TOKEN_SECRET"])
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    cli.main(["team", "export", "--to", f"file:{bundle_file}"])                     # the lead publishes
    monkeypatch.delenv("VEIL_TOKEN_SECRET")
    monkeypatch.setenv("VEIL_HOME", str(home / "dev"))                            # a teammate
    v = state.load()
    v.known.add("leonekohler@surfeu.de", "email", "c:2")
    old_tok = v.redact("mail leonekohler@surfeu.de")                              # used before joining
    cli.main(["team", "join", "--from", f"file:{bundle_file}", "--reset-vault"])
    assert get_key("token-secret", str(home / "dev")) == b"L" * 32
    assert state.config()["team_source"] == f"file:{bundle_file}"
    v = state.load()
    v.known.add("leonekohler@surfeu.de", "email", "c:2")
    assert v.rehydrate(old_tok) == "mail leonekohler@surfeu.de"                    # retired, still restores
    team_tok = v.redact("mail leonekohler@surfeu.de")
    assert team_tok != old_tok
    cli.main(["team", "sync"]); assert "unchanged" in capsys.readouterr().err
    # the lead rotates the team secret and republishes; teammates sync
    from veil import team
    bundle_file.write_text(team.export_bundle(b"N" * 32, []))
    cli.main(["team", "sync"]); assert "team secret updated" in capsys.readouterr().err
    v = state.load()
    v.known.add("leonekohler@surfeu.de", "email", "c:2")
    assert v.redact("mail leonekohler@surfeu.de") not in (old_tok, team_tok) and v.rehydrate(team_tok).endswith("surfeu.de")
