import pytest


@pytest.fixture(autouse=True)
def _no_real_key_stores(monkeypatch, tmp_path_factory):
    """Tests never touch the developer's real Keychain, Secret Service or Credential
    Manager. Tests that exercise a store opt back in explicitly."""
    monkeypatch.setenv("VEIL_KEYCHAIN", str(tmp_path_factory.getbasetemp() / "no-such.keychain"))
    monkeypatch.setenv("VEIL_SECRET_SERVICE", "0")
    monkeypatch.setenv("VEIL_WINCRED", "0")
