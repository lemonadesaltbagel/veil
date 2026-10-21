"""Windows support: Startup-folder service, Credential Manager keys, hook path quoting.
The Credential Manager test runs only on Windows (CI windows-latest)."""

import os
import subprocess
import sys
import time

import pytest

from veil import adopt, keys


def test_launcher_runs_hidden_with_home_and_no_env_keys(monkeypatch):
    monkeypatch.setenv("VEIL_VAULT_KEY", "c2VjcmV0")
    vbs = adopt.windows_launcher(8787, "https://api.anthropic.com", False, r"C:\Users\ann\.veil")
    assert 'sh.Environment("Process")("VEIL_HOME") = "C:\\Users\\ann\\.veil"' in vbs
    assert vbs.rstrip().endswith(", 0, False")          # window style 0 = hidden, don't wait
    assert '""--pid-file""' in vbs and "c2VjcmV0" not in vbs and "VEIL_VAULT_KEY" not in vbs


def test_install_status_uninstall_stops_the_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_STARTUP_DIR", str(tmp_path / "Startup"))
    path = adopt.windows_install(1, "https://api.anthropic.com", False, str(tmp_path), start=False)
    assert os.path.exists(path) and "installed" in adopt.windows_status(1)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    (tmp_path / "proxy.pid").write_text(str(proc.pid))
    assert adopt.windows_uninstall(str(tmp_path))
    assert proc.wait(timeout=10) is not None and not os.path.exists(path)


def test_hook_paths_with_backslashes_are_quoted():
    assert adopt._q(r"C:\Users\ann\venv\Scripts\python.exe") == r'"C:\Users\ann\venv\Scripts\python.exe"'
    assert adopt._q("/usr/bin/python3") == "/usr/bin/python3"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager")
def test_credential_manager_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("VEIL_WINCRED", raising=False)
    name = f"test-key-{os.getpid()}-{int(time.time())}"
    try:
        assert keys.peek_key(name, str(tmp_path)) is None
        assert keys.set_key(name, str(tmp_path), b"k" * 32) == "credential-manager"
        assert keys.peek_key(name, str(tmp_path)) == b"k" * 32
        assert not (tmp_path / "keys" / name).exists()      # not a file fallback
    finally:
        keys.delete_key(name, str(tmp_path))
    assert keys.peek_key(name, str(tmp_path)) is None
