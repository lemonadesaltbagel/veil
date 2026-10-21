"""Pilot: a real coding task in a real repository, through veil, with a real model.

    uv run python -m veil_dev.pilot --repo ~/code/myapp --task "add a --version flag" \\
        --seed postgresql://... --upstream https://api.deepseek.com/anthropic \\
        --api-key-env DEEPSEEK_API_KEY --model deepseek-flash

The repo is cloned to a scratch directory (your checkout is never touched). Claude Code
works on it with read/search/edit tools and `uv run pytest`. The report answers:
did the task succeed; every replacement the model saw, with context (false-positive
review); did a pseudonym get written into the code; leaks; cost.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter

from veil.detect import KnownValues
from veil.engine import Veil
from veil.sources import seed, seed_environment
from veil.vault import Vault
from veil_dev.audit import _load_env_key
from veil_dev.testing import Recorder, find_leaks, start_proxy

TOKEN_IN_CODE = re.compile(r"\b(?:user_[a-z2-9]{4,6}(?:\+\d+)?@example\.test|user_[a-z2-9]{4,6}|First_[A-Z][a-z2-9]{3,5}|"
                           r"Last_[A-Z][a-z2-9]{3,5}|card_[a-z2-9]{4,6}|secret_[a-z2-9]{4,6})\b")


def _strings(o, path=""):
    if isinstance(o, str):
        yield path, o
    elif isinstance(o, list):
        for i, x in enumerate(o):
            yield from _strings(x, f"{path}[{i}]")
    elif isinstance(o, dict):
        for k, x in o.items():
            yield from _strings(x, f"{path}.{k}" if path else k)


def replacements(veil: Veil, exchanges: list[dict]) -> list[dict]:
    """Every (real value -> token) the model saw, with where and the surrounding context."""
    pattern = veil.token_pattern()
    seen: dict[tuple, dict] = {}
    for e in exchanges:
        sent, orig = e.get("sent"), e.get("original")
        if not sent or not orig:
            continue
        orig_by_path = dict(_strings(orig))
        for path, s in _strings(sent):
            for m in pattern.finditer(s) if pattern else []:
                tok = m.group()
                real = veil.vault.value_for(tok) or "?"
                where = "system" if path.startswith("system") else ("tools" if path.startswith("tools") else "messages")
                key = (real, tok, where)
                if key not in seen:
                    o = orig_by_path.get(path, "")
                    i = o.find(real)
                    ctx = o[max(0, i - 50):i + len(real) + 50].replace("\n", " ") if i >= 0 else ""
                    seen[key] = {"real": real, "token": tok, "where": where, "count": 0, "context": ctx}
                seen[key]["count"] += 1
    return sorted(seen.values(), key=lambda r: -r["count"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="veil_dev.pilot")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--task", required=True)
    ap.add_argument("--seed", nargs="*", default=[])
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--api-key-env", default="ANTHROPIC_API_KEY")
    ap.add_argument("--model")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-turns", type=int, default=25)
    args = ap.parse_args(argv)

    out = os.path.abspath(args.out)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    ws = os.path.join(out, "repo")
    subprocess.run(["git", "clone", "-q", os.path.abspath(os.path.expanduser(args.repo)), ws], check=True)

    known = KnownValues()
    for src in args.seed:
        seed(known, src)
    seed_environment(known)
    veil = Veil(Vault(":memory:", os.urandom(32)), known)
    rec = Recorder()
    px = start_proxy(veil, args.upstream, rec, log=open(os.path.join(out, "veil.log"), "w"))
    key = _load_env_key(args.api_key_env)
    config_dir = tempfile.mkdtemp(prefix="veil-pilot-claude-")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CLAUDE", "ANTHROPIC")) and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env.update({"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{px.server_port}", "ANTHROPIC_API_KEY": key or "",
                "CLAUDE_CONFIG_DIR": config_dir, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_AUTOUPDATER": "1", "API_TIMEOUT_MS": "300000", "NO_PROXY": "127.0.0.1,localhost"})
    if args.model:
        for var in ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL"):
            env[var] = args.model
    cmd = ["claude", "-p", args.task, "--output-format", "json", "--max-turns", str(args.max_turns),
           "--allowedTools", "Read", "Grep", "Glob", "Edit", "Write", "Bash(uv run pytest:*)", "Bash(git diff:*)",
           "Bash(git status:*)", "Bash(uv sync:*)"]
    try:
        p = subprocess.run(cmd, cwd=ws, env=env, capture_output=True, text=True, timeout=1800)
    finally:
        px.shutdown()
        shutil.rmtree(config_dir, ignore_errors=True)

    try:
        result = json.loads(p.stdout)
    except json.JSONDecodeError:
        result = {"result": p.stdout[-3000:] + p.stderr[-2000:], "is_error": True}
    diff = subprocess.run(["git", "diff"], cwd=ws, capture_output=True, text=True).stdout
    diffstat = subprocess.run(["git", "diff", "--stat"], cwd=ws, capture_output=True, text=True).stdout
    added = "\n".join(l for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    tokens_in_code = sorted(set(TOKEN_IN_CODE.findall(added)))
    leaks = {i: L for i, e in enumerate(rec.exchanges, 1) if e.get("sent")
             and (L := find_leaks(json.dumps(e["sent"], ensure_ascii=False), sorted(known._entries, key=len, reverse=True)))}
    reps = replacements(veil, rec.exchanges)
    usage = Counter()
    for e in rec.exchanges:
        for k, v in ((e.get("model_view") or {}).get("usage") or {}).items():
            if isinstance(v, int):
                usage[k] += v

    lines = [f"# Pilot report", "", f"- repo: `{args.repo}` (cloned to scratch)", f"- task: {args.task}",
             f"- seeded values: {len(known)}", f"- model requests: {len(rec.exchanges)}",
             f"- task finished: {not result.get('is_error')} after {result.get('num_turns')} turns",
             f"- leaks of seeded values: **{sum(map(len, leaks.values()))}** {leaks if leaks else ''}",
             f"- pseudonyms written into the code: **{len(tokens_in_code)}** {tokens_in_code if tokens_in_code else ''}",
             f"- usage: {dict(usage)}", "", "## Final answer", "", result.get("result", "")[:3000], "",
             "## Diff", "", "```text", diffstat, "```", "", "```diff", diff[:6000], "```", "",
             f"## Every replacement the model saw ({len(reps)})", "",
             "Review for false positives: is the real value really personal data in this context?", "",
             "| where | real value | token | × | context |", "|---|---|---|---|---|"]
    for r in reps:
        ctx = r["context"].replace("|", "\\|")[:120]
        lines.append(f"| {r['where']} | `{r['real']}` | `{r['token']}` | {r['count']} | {ctx} |")
    with open(os.path.join(out, "PILOT.md"), "w") as f:
        f.write("\n".join(lines))
    for i, e in enumerate(rec.exchanges, 1):  # exactly what the model received (pseudonyms only)
        if e.get("sent"):
            with open(os.path.join(out, f"{i:02d}_llm_received.json"), "w") as f:
                json.dump(e["sent"], f, ensure_ascii=False, indent=1)
    print("\n".join(lines[:12]))
    print(f"\nreplacements: {len(reps)} -> {os.path.join(out, 'PILOT.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
