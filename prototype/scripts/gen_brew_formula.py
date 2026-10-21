"""Generate packaging/homebrew/veil.rb from uv.lock (resource pins + sha256, no network).

    uv run python scripts/gen_brew_formula.py --url <release sdist url> --sha256 <sdist sha256>

Homebrew's own `cryptography` formula is used instead of building it (needs Rust).
"""

import argparse
import hashlib
import os
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = {"veil-proxy", "cryptography", "cffi", "pycparser"}  # provided by `depends_on "cryptography"`


def core_closure(lock: dict) -> list[dict]:
    pkgs = {p["name"]: p for p in lock["package"]}
    todo, seen = [d["name"] for d in pkgs["veil-proxy"].get("dependencies", [])], set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo += [d["name"] for d in pkgs[name].get("dependencies", []) if "marker" not in d or "win32" not in d["marker"]]
    return [pkgs[n] for n in sorted(seen - SKIP)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://github.com/lemonadesaltbagel/veil/releases/download/v0.1.0/veil_proxy-0.1.0.tar.gz")
    ap.add_argument("--sha256")
    args = ap.parse_args()
    sdist = os.path.join(ROOT, "dist", "veil_proxy-0.1.0.tar.gz")
    sha = args.sha256 or (hashlib.sha256(open(sdist, "rb").read()).hexdigest() if os.path.exists(sdist) else "TODO")
    lock = tomllib.load(open(os.path.join(ROOT, "uv.lock"), "rb"))
    res = ""
    for p in core_closure(lock):
        sd = p.get("sdist")
        if not sd:
            raise SystemExit(f"{p['name']} has no sdist in uv.lock")
        res += f'  resource "{p["name"]}" do\n    url "{sd["url"]}"\n    sha256 "{sd["hash"].split(":", 1)[1]}"\n  end\n\n'
    rb = f'''class Veil < Formula
  include Language::Python::Virtualenv

  desc "Privacy proxy for AI coding agents: models see pseudonyms, you keep real values"
  homepage "https://github.com/lemonadesaltbagel/veil"
  url "{args.url}"
  sha256 "{sha}"

  depends_on "cryptography"
  depends_on "python@3.13"

{res}  def install
    virtualenv_install_with_resources
  end

  service do
    run [opt_bin/"veil", "proxy", "--port", "8787"]
    keep_alive true
    environment_variables NO_PROXY: "127.0.0.1,localhost"
    log_path var/"log/veil.log"
    error_log_path var/"log/veil.log"
  end

  test do
    ENV["VEIL_HOME"] = testpath/".veil"
    ENV["VEIL_VAULT_KEY"] = "dGVzdC12YXVsdC1rZXktMzItYnl0ZXMtbG9uZyEhISE="   # test-only keys: no keychain
    ENV["VEIL_TOKEN_SECRET"] = "dGVzdC10b2tlbi1zZWNyZXQtMzItYnl0ZXMtbG9uZyE="
    assert_match "usage: veil", shell_output("#{{bin}}/veil --help")
    assert_match "user_", pipe_output("#{{bin}}/veil redact", "mail jane.roe@mailbox.org\\n")
  end
end
'''
    out = os.path.join(ROOT, "packaging", "homebrew", "veil.rb")
    open(out, "w").write(rb)
    print(out)


if __name__ == "__main__":
    main()
