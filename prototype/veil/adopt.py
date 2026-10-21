"""Adoption: `veil init`, `veil status`, `veil service` (macOS LaunchAgent).

`veil init` finds a project's data sources, seeds them, and writes a project-local
`.claude/settings.local.json` (merged, never clobbered; git-ignored) that routes
Claude Code through the proxy and adds veil's hooks as a backup layer.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
import urllib.request

URL_VARS = re.compile(r"^\s*(?:export\s+)?([A-Z0-9_]*(?:DATABASE|DB|POSTGRES|PG|MYSQL|MARIADB|MONGO|MONGODB|REDIS)"
                      r"[A-Z0-9_]*(?:URL|URI|DSN))\s*=\s*['\"]?([^'\"\s#]+)", re.M)
SCHEMES = ("postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://", "mongodb+srv://",
           "redis://", "rediss://", "sqlite:", "file:")
FIXTURE_DIRS = re.compile(r"^(fixtures?|seeds?|seed_data|testdata|test_data|sample[-_]?data|mock[-_]?data)$", re.I)
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".veil", ".next", "target"}
LABEL = os.environ.get("VEIL_SERVICE_LABEL", "dev.veil.proxy")


def detect_sources(project: str) -> list[tuple[str, str]]:
    """[(source, where it was found)] -- credentials stay in the source string, never printed."""
    found: dict[str, str] = {}
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP]
        depth = root[len(project):].count(os.sep)
        for f in files:
            path = os.path.join(root, f)
            rel = os.path.relpath(path, project)
            if f.startswith(".env") and depth <= 2:
                try:
                    for var, url in URL_VARS.findall(open(path, errors="ignore").read()):
                        if url.startswith(SCHEMES):
                            found.setdefault(url, f"{rel}:{var}")
                except OSError:
                    pass
            elif f.endswith((".sqlite", ".sqlite3", ".db")) and os.path.getsize(path) < 2_000_000_000:
                found.setdefault(path, rel)
        for d in list(dirs):
            if FIXTURE_DIRS.match(d):
                found.setdefault(os.path.join(root, d), os.path.relpath(os.path.join(root, d), project) + "/")
    return list(found.items())


def redact_uri(uri: str) -> str:
    return re.sub(r"//([^:@/]+)(:[^@/]*)?@", r"//\1:***@", uri)


def state_home() -> str:
    from .state import home
    return home()


def veil_command() -> list[str]:
    """How hooks and the service invoke veil (absolute; independent of cwd/venv activation)."""
    return [sys.executable, "-m", "veil.cli"]


def write_claude_settings(project: str, port: int, hooks: bool = True, deny_env: bool = False) -> str:
    d = os.path.join(project, ".claude")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "settings.local.json")
    settings = {}
    if os.path.exists(path):
        try:
            settings = json.load(open(path))
        except ValueError:
            raise SystemExit(f"{path} is not valid JSON; fix it before running veil init")
    env = settings.setdefault("env", {})
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{port}"
    no_proxy = {h for h in env.get("NO_PROXY", "").split(",") if h} | {"127.0.0.1", "localhost"}
    env["NO_PROXY"] = ",".join(sorted(no_proxy))
    if hooks:
        cmd = " ".join(f'"{c}"' if " " in c else c for c in veil_command())
        all_hooks = settings.setdefault("hooks", {})
        for event, kind in (("PreToolUse", "pre"), ("PostToolUse", "post")):
            entries = [e for e in all_hooks.get(event, [])
                       if "veil.cli hook" not in json.dumps(e) and "veil.hookclient" not in json.dumps(e)]
            fast = " ".join(f'"{c}"' if " " in c else c for c in [sys.executable, "-m", "veil.hookclient"])
            home = state_home()
            home_arg = f' --home "{home}"' if " " in home else f" --home {home}"
            entries.append({"matcher": "*", "hooks": [{"type": "command",
                                                       "command": f"{fast} {kind} --port {port}{home_arg}"}]})
            all_hooks[event] = entries
    if deny_env:
        deny = settings.setdefault("permissions", {}).setdefault("deny", [])
        for rule in ("Read(./.env)", "Read(./.env.*)"):
            if rule not in deny:
                deny.append(rule)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    gi = os.path.join(project, ".gitignore")
    if os.path.isdir(os.path.join(project, ".git")):
        lines = open(gi).read().splitlines() if os.path.exists(gi) else []
        if ".claude/settings.local.json" not in lines:
            with open(gi, "a") as f:
                f.write(("\n" if lines and lines[-1] else "") + ".claude/settings.local.json\n")
    return path


def health(port: int, timeout: float = 2.0) -> dict | None:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # bypass system proxies
        with opener.open(f"http://127.0.0.1:{port}/veil/health", timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


# -- macOS LaunchAgent ----------------------------------------------------------

def agents_dir() -> str:
    return os.environ.get("VEIL_LAUNCH_AGENTS_DIR", os.path.expanduser("~/Library/LaunchAgents"))


def plist_path() -> str:
    return os.path.join(agents_dir(), f"{LABEL}.plist")


def service_plist(port: int, upstream: str, ner: bool, home: str, capture: str | None = None) -> dict:
    args = veil_command() + ["proxy", "--port", str(port), "--upstream", upstream] + (["--ner"] if ner else []) \
        + (["--capture", capture] if capture else [])
    env = {"VEIL_HOME": home, "NO_PROXY": "127.0.0.1,localhost"}
    for k in ("VEIL_VAULT_KEY", "VEIL_TOKEN_SECRET", "VEIL_KEYCHAIN"):  # only if the caller uses them
        if os.environ.get(k):
            env[k] = os.environ[k]
    return {"Label": LABEL, "ProgramArguments": args, "RunAtLoad": True, "KeepAlive": True,
            "EnvironmentVariables": env, "WorkingDirectory": home,
            "StandardOutPath": os.path.join(home, "proxy.log"), "StandardErrorPath": os.path.join(home, "proxy.log")}


def service_install(port: int, upstream: str, ner: bool, home: str, load: bool = True,
                    capture: str | None = None) -> str:
    os.makedirs(agents_dir(), exist_ok=True)
    path = plist_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may carry env keys: owner-only
    with os.fdopen(fd, "wb") as f:
        plistlib.dump(service_plist(port, upstream, ner, home, capture), f)
    if load:
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"], capture_output=True)
        # bootout is asynchronous: wait for the old instance to unload, then (re)try bootstrap
        for _ in range(50):
            if service_status() == "not loaded":
                break
            time.sleep(0.1)
        for attempt in range(5):
            r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", path], capture_output=True, text=True)
            if r.returncode == 0:
                break
            time.sleep(0.5 * (attempt + 1))
        else:
            raise SystemExit(f"launchctl bootstrap failed: {r.stderr.strip()}")
    return path


def service_uninstall() -> bool:
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], capture_output=True)
    if os.path.exists(plist_path()):
        os.remove(plist_path())
        return True
    return False


def service_status() -> str:
    r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True)
    if r.returncode != 0:
        return "not loaded"
    m = re.search(r"state = (\w+)", r.stdout)
    pid = re.search(r"pid = (\d+)", r.stdout)
    return f"{m.group(1) if m else 'loaded'}" + (f" (pid {pid.group(1)})" if pid else "")


# -- Linux: systemd user unit ---------------------------------------------------------

UNIT = "veil-proxy.service"


def systemd_dir() -> str:
    return os.environ.get("VEIL_SYSTEMD_DIR", os.path.expanduser("~/.config/systemd/user"))


def systemd_unit(port: int, upstream: str, ner: bool, home: str, capture: str | None = None) -> str:
    plist = service_plist(port, upstream, ner, home, capture)
    q = lambda a: '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"' if any(c in a for c in ' "\'') else a
    env = "\n".join(f'Environment="{k}={v}"' for k, v in plist["EnvironmentVariables"].items())
    return f"""[Unit]
Description=veil privacy proxy for AI coding agents
After=network-online.target

[Service]
ExecStart={" ".join(q(a) for a in plist["ProgramArguments"])}
{env}
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={home}

[Install]
WantedBy=default.target
"""


def systemd_install(port: int, upstream: str, ner: bool, home: str, load: bool = True,
                    capture: str | None = None) -> str:
    os.makedirs(systemd_dir(), exist_ok=True)
    path = os.path.join(systemd_dir(), UNIT)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may carry env keys: owner-only
    with os.fdopen(fd, "w") as f:
        f.write(systemd_unit(port, upstream, ner, home, capture))
    if load:
        for args in (["daemon-reload"], ["enable", "--now", UNIT], ["restart", UNIT]):
            r = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"systemctl --user {' '.join(args)} failed: {r.stderr.strip()}")
    return path


def systemd_uninstall() -> bool:
    subprocess.run(["systemctl", "--user", "disable", "--now", UNIT], capture_output=True)
    path = os.path.join(systemd_dir(), UNIT)
    if os.path.exists(path):
        os.remove(path)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        return True
    return False


def systemd_status() -> str:
    r = subprocess.run(["systemctl", "--user", "is-active", UNIT], capture_output=True, text=True)
    return r.stdout.strip() or "not loaded"
