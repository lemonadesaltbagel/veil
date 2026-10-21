"""veil init / status / service plumbing (no databases needed)."""

import json
import os
import plistlib
import shutil
import subprocess
import threading
from http.server import ThreadingHTTPServer

import httpx

from veil import adopt
from veil.anthropic import Policy
from veil.detect import KnownValues
from veil.engine import Veil
from veil.proxy import make_handler
from veil.vault import Vault


def make_project(tmp_path):
    p = tmp_path / "shop"
    (p / "fixtures").mkdir(parents=True)
    (p / "node_modules" / "x" / "fixtures").mkdir(parents=True)
    (p / ".git").mkdir()
    (p / ".env").write_text("DATABASE_URL=postgresql://app:s3cret@localhost:5432/shop\n"
                            "export REDIS_URL='redis://localhost:6379/0'\nSECRET_KEY=abc\n")
    (p / ".env.test").write_text("MONGODB_URI=mongodb://localhost:27017/shop_test\n")
    (p / "dev.sqlite3").write_bytes(b"")
    (p / "fixtures" / "users.json").write_text("[]")
    return p


def test_detect_sources(tmp_path):
    p = make_project(tmp_path)
    found = dict(adopt.detect_sources(str(p)))
    assert found["postgresql://app:s3cret@localhost:5432/shop"] == ".env:DATABASE_URL"
    assert found["redis://localhost:6379/0"] == ".env:REDIS_URL"
    assert found["mongodb://localhost:27017/shop_test"] == ".env.test:MONGODB_URI"
    assert str(p / "dev.sqlite3") in found and str(p / "fixtures") in found
    assert not any("node_modules" in k for k in found)
    assert adopt.redact_uri("postgresql://app:s3cret@localhost/shop") == "postgresql://app:***@localhost/shop"


def test_settings_merge_is_idempotent_and_preserves_user_config(tmp_path):
    p = make_project(tmp_path)
    (p / ".claude").mkdir()
    (p / ".claude" / "settings.local.json").write_text(json.dumps({
        "permissions": {"allow": ["Bash(npm test)"]},
        "hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "prettier"}]}]}}))
    for _ in range(2):  # running init twice must not duplicate hooks
        path = adopt.write_claude_settings(str(p), 8787, deny_env=True)
    s = json.load(open(path))
    assert s["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8787"
    assert "127.0.0.1" in s["env"]["NO_PROXY"]
    assert s["permissions"]["allow"] == ["Bash(npm test)"] and "Read(./.env)" in s["permissions"]["deny"]
    post = s["hooks"]["PostToolUse"]
    assert post[0]["hooks"][0]["command"] == "prettier"                     # user's hook kept
    assert sum("veil.hookclient post" in json.dumps(e) for e in post) == 1    # exactly one veil hook
    assert ".claude/settings.local.json" in (p / ".gitignore").read_text()


def test_health_endpoint_reports_counts_not_values():
    known = KnownValues(); known.add("leonekohler@surfeu.de", "email", "c")
    veil = Veil(Vault(":memory:", b"s"), known)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(veil, Policy(), "http://127.0.0.1:9", httpx.Client()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        h = adopt.health(srv.server_port)
        assert h["ok"] and h["known_values"] >= 1 and "leonekohler" not in json.dumps(h)
    finally:
        srv.shutdown()


def test_launch_agent_plist(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_LAUNCH_AGENTS_DIR", str(tmp_path))
    path = adopt.service_install(8787, "https://api.anthropic.com", False, str(tmp_path / "home"), load=False)
    plist = plistlib.load(open(path, "rb"))
    assert plist["ProgramArguments"][-4:] == ["--port", "8787", "--upstream", "https://api.anthropic.com"]
    assert plist["KeepAlive"] and plist["EnvironmentVariables"]["VEIL_HOME"].endswith("home")
    if shutil.which("plutil"):  # macOS only
        assert subprocess.run(["plutil", "-lint", path], capture_output=True).returncode == 0


def test_per_project_home_reaches_the_hooks(tmp_path, monkeypatch):
    # a second proxy with its own vault: VEIL_HOME=~/.veil-acme veil init PROJECT --port 8788
    monkeypatch.setenv("VEIL_HOME", str(tmp_path / "veil-acme"))
    p = make_project(tmp_path)
    s = json.load(open(adopt.write_claude_settings(str(p), 8788)))
    cmd = s["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
    assert cmd.endswith(f"pre --port 8788 --home {adopt._q(str(tmp_path / 'veil-acme'))}")
    assert s["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8788"
