"""`veil audit`: run a realistic agent session through veil and report exactly
what the LLM received.

    veil audit                                   # real Claude Code -> veil -> fake LLM (offline)
    veil audit --driver sdk                      # Anthropic SDK loop -> veil -> fake LLM
    veil audit --upstream https://api.deepseek.com/anthropic \\
               --api-key-env DEEPSEEK_API_KEY --model deepseek-flash   # real model

Scenario: sample Chinook DB + a billing log; the user asks about one customer.
Real models get tightly limited tools: read-only commands inside a scratch
workspace only. Exit status 1 if any real value reached the upstream.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

from veil.detect import KnownValues
from veil.engine import Veil
from veil.sources import seed_environment, seed_sqlite
from veil_dev.testing import (EXTRA_REAL_VALUES, PROMPT, Recorder, make_app_log, start_mock_cloud, start_mock_llm, start_mock_responses,
                      start_proxy, write_captures)
from veil.vault import Vault

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))  # prototype/
CHINOOK = os.path.join(ROOT, "datasets", "chinook.sqlite")
SDK_TOOLS = [
    {"name": "Bash", "description": "Run a read-only shell command in the working directory "
                                    "(sqlite3, grep, cat, head, tail, wc).",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "Read", "description": "Read a file in the working directory. Returns cat -n style lines.",
     "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}},
]
SAFE_COMMANDS = {"sqlite3", "grep", "cat", "head", "tail", "wc", "ls", "echo"}


def scenario(out_dir: str) -> tuple[Veil, list[str], str]:
    shutil.rmtree(out_dir, ignore_errors=True)
    ws = os.path.join(out_dir, "workspace")  # under $HOME: paths carry the OS username
    os.makedirs(ws)
    shutil.copy(CHINOOK, os.path.join(ws, "chinook.sqlite"))
    make_app_log(CHINOOK, os.path.join(ws, "app.log"))
    veil = Veil(Vault(":memory:", os.urandom(32)), KnownValues())
    seed_sqlite(veil.known, CHINOOK)
    seed_environment(veil.known)
    return veil, list(veil.known._entries) + EXTRA_REAL_VALUES, ws


def _run_tool(name: str, tool_input: dict, ws: str) -> str:
    """Harness-side tool execution with hard limits (a real model picks the commands)."""
    if name == "Bash":
        # Executed as argv without a shell, so ; | > inside arguments are inert.
        cmd = tool_input.get("command", "")
        try:
            argv = [a for a in shlex.split(cmd) if a != "2>&1"]
        except ValueError:
            return "denied: unparseable command"
        if not argv or argv[0] not in SAFE_COMMANDS:
            return f"denied by audit harness: only read-only commands ({', '.join(sorted(SAFE_COMMANDS))})"
        root = os.path.realpath(ws)
        for a in argv[1:]:
            if a.startswith(("/", "~")) or ".." in a:
                if not os.path.realpath(os.path.join(ws, os.path.expanduser(a))).startswith(root):
                    return "denied by audit harness: path outside the working directory"
        if argv[0] == "sqlite3":  # no .shell/.system/ATTACH, no writes
            argv = ["sqlite3", "-safe", "-readonly", *argv[1:]]
        p = subprocess.run(argv, cwd=ws, capture_output=True, text=True, timeout=30)
        return ((p.stdout + p.stderr).strip() or "(no output)")[:20000]
    if name == "Read":
        path = os.path.realpath(os.path.join(ws, tool_input.get("file_path", "")))
        if not path.startswith(os.path.realpath(ws) + os.sep):
            return "denied by audit harness: outside the working directory"
        try:
            with open(path) as f:
                return "".join(f"{i:6}\t{line}" for i, line in enumerate(f, 1))[:20000]
        except OSError as e:
            return f"error: {e.strerror}"
    return f"unknown tool {name}"


def run_sdk(proxy_url: str, api_key: str, model: str, ws: str, max_turns: int = 8) -> tuple[str, list]:
    import anthropic
    import httpx2

    client = anthropic.Anthropic(base_url=proxy_url, api_key=api_key, max_retries=1,
                                 http_client=httpx2.Client(trust_env=False, timeout=300))
    import getpass
    system = (f"You are a coding agent working in a local repository.\n<env>\nPrimary working directory: {ws}\n"
              f"OS user: {getpass.getuser()}\n</env>\nUse the tools to investigate; be concise.")
    messages: list[dict] = [{"role": "user", "content": PROMPT}]
    executed = []
    for _ in range(max_turns):
        with client.messages.stream(model=model, max_tokens=2048, system=system, tools=SDK_TOOLS,
                                    messages=messages) as stream:
            msg = stream.get_final_message()
        messages.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in msg.content]})
        uses = [b for b in msg.content if b.type == "tool_use"]
        if not uses:
            break
        results = []
        for u in uses:
            executed.append({"tool": u.name, "input": u.input})
            results.append({"type": "tool_result", "tool_use_id": u.id, "content": _run_tool(u.name, u.input, ws)})
        messages.append({"role": "user", "content": results})
    final = "\n".join(b.get("text", "") for b in messages[-1]["content"] if isinstance(b, dict)) \
        if messages[-1]["role"] == "assistant" else "(stopped after max turns)"
    return final, executed


OPENAI_TOOLS = [
    {"type": "function", "function": {"name": "shell", "description": "Run a read-only shell command in the "
     "working directory (sqlite3, grep, cat, head, tail, wc).", "parameters": {"type": "object", "properties": {
         "command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "read_file", "description": "Read a file in the working directory.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
]


def _openai_client(base_url: str, api_key: str):
    import openai
    for mod in ("httpx2", "httpx"):  # SDK generations differ in their HTTP client package
        try:
            http = __import__(mod).Client(trust_env=False, timeout=300)
            return openai.OpenAI(base_url=base_url, api_key=api_key, max_retries=1, http_client=http)
        except (ImportError, TypeError):
            continue
    return openai.OpenAI(base_url=base_url, api_key=api_key, max_retries=1)


def run_openai(proxy_url: str, api_key: str, model: str, ws: str, max_turns: int = 15) -> tuple[str, list]:
    """OpenAI Chat Completions agent loop (streaming), as Aider/Continue-style clients do."""
    import getpass
    client = _openai_client(proxy_url, api_key)
    messages: list[dict] = [
        {"role": "system", "content": f"You are a coding agent. Working directory: {ws}. OS user: {getpass.getuser()}. "
                                      "Use the tools to investigate; be concise."},
        {"role": "user", "content": PROMPT}]
    executed = []
    for _ in range(max_turns):
        stream = client.chat.completions.create(model=model, messages=messages, tools=OPENAI_TOOLS, stream=True)
        text, calls = "", {}
        for chunk in stream:
            for ch in chunk.choices:
                d = ch.delta
                text += d.content or ""
                for tc in d.tool_calls or []:
                    c = calls.setdefault(tc.index, {"id": None, "name": "", "arguments": ""})
                    c["id"] = tc.id or c["id"]
                    if tc.function:
                        c["name"] += tc.function.name or ""
                        c["arguments"] += tc.function.arguments or ""
        msg = {"role": "assistant", "content": text or None}
        if calls:
            msg["tool_calls"] = [{"id": c["id"], "type": "function", "function": {"name": c["name"],
                                 "arguments": c["arguments"]}} for _, c in sorted(calls.items())]
        messages.append(msg)
        if not calls:
            return text, executed
        for _, c in sorted(calls.items()):
            args = json.loads(c["arguments"] or "{}")
            executed.append({"tool": c["name"], "input": args})
            if c["name"] == "shell":
                result = _run_tool("Bash", {"command": args.get("command", "")}, ws)
            elif c["name"] == "read_file":
                result = _run_tool("Read", {"file_path": args.get("path", "")}, ws)
            else:
                result = f"unknown tool {c['name']}"
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": result})
    return "(stopped after max turns)", executed


def run_codex(proxy_url: str, api_key: str, model: str | None, ws: str, max_turns: int = 15) -> tuple[str, list]:
    """Real Codex CLI (`codex exec`) in an isolated CODEX_HOME whose provider points at veil."""
    home = tempfile.mkdtemp(prefix="veil-codex-home-")
    with open(os.path.join(home, "config.toml"), "w") as f:
        f.write(f'model = "{model or "gpt-6"}"\nmodel_provider = "veil"\n[model_providers.veil]\n'
                f'name = "veil"\nbase_url = "{proxy_url}/v1"\nenv_key = "VEIL_CODEX_KEY"\nwire_api = "responses"\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX", "OPENAI"))
           and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env.update({"CODEX_HOME": home, "VEIL_CODEX_KEY": api_key, "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost"})
    try:
        p = subprocess.run(["codex", "exec", "--skip-git-repo-check", "-s", "read-only", PROMPT], cwd=ws, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    for name, data in (("codex_stdout.txt", p.stdout), ("codex_stderr.txt", p.stderr)):
        with open(os.path.join(os.path.dirname(ws), name), "w") as f:
            f.write(data)
    return (p.stdout.strip() or p.stderr[-2000:]), []


def run_claude(proxy_url: str, api_key: str, model: str | None, ws: str, max_turns: int = 15,
               provider: str = "anthropic") -> tuple[str, list]:
    config_dir = tempfile.mkdtemp(prefix="veil-claude-config-")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CLAUDE", "ANTHROPIC")) and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env.update({"ANTHROPIC_BASE_URL": proxy_url, "ANTHROPIC_API_KEY": api_key, "CLAUDE_CONFIG_DIR": config_dir,
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1",
                "API_TIMEOUT_MS": "300000", "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
    if provider == "bedrock":   # Claude Code speaks Bedrock InvokeModel to veil; veil adds AWS auth
        env.pop("ANTHROPIC_BASE_URL"); env.pop("ANTHROPIC_API_KEY")
        env.update({"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_BEDROCK_BASE_URL": proxy_url,
                    "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1", "AWS_REGION": "us-east-1"})
    elif provider == "foundry":  # Microsoft Foundry: Anthropic Messages under /foundry; key passes through
        env.pop("ANTHROPIC_BASE_URL"); env.pop("ANTHROPIC_API_KEY")
        env.update({"CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_BASE_URL": proxy_url + "/foundry",
                    "ANTHROPIC_FOUNDRY_API_KEY": api_key})
    elif provider == "anthropic-aws":  # Claude Platform on AWS: veil signs (SigV4) after redaction
        env.pop("ANTHROPIC_BASE_URL"); env.pop("ANTHROPIC_API_KEY")
        env.update({"CLAUDE_CODE_USE_ANTHROPIC_AWS": "1", "ANTHROPIC_AWS_BASE_URL": proxy_url + "/anthropic-aws",
                    "ANTHROPIC_AWS_WORKSPACE_ID": "wrkspc_veil_audit", "CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH": "1",
                    "AWS_REGION": "us-east-1"})
    elif provider == "vertex":  # Claude Code speaks Vertex rawPredict to veil; veil adds the Google token
        env.pop("ANTHROPIC_BASE_URL"); env.pop("ANTHROPIC_API_KEY")
        env.update({"CLAUDE_CODE_USE_VERTEX": "1", "ANTHROPIC_VERTEX_BASE_URL": proxy_url + "/v1",
                    "CLAUDE_CODE_SKIP_VERTEX_AUTH": "1", "ANTHROPIC_VERTEX_PROJECT_ID": "veil-test",
                    "CLOUD_ML_REGION": "us-east5"})
    if model:  # route every Claude Code model slot to the same (cheap) upstream model
        for var in ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL"):
            env[var] = model
    cmd = ["claude", "-p", PROMPT, "--output-format", "json", "--max-turns", str(max_turns),
           "--allowedTools", "Bash(sqlite3:*)", "Read(./**)"]
    try:
        p = subprocess.run(cmd, cwd=ws, env=env, capture_output=True, text=True, timeout=600)
    finally:
        shutil.rmtree(config_dir, ignore_errors=True)
    try:
        out = json.loads(p.stdout)
        return out.get("result", "") or json.dumps(out)[:2000], []
    except json.JSONDecodeError:
        return f"(exit {p.returncode}) {p.stdout[-1500:]} {p.stderr[-1500:]}", []


def _load_env_key(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    d = os.getcwd()
    while True:
        path = os.path.join(d, ".env")
        if os.path.exists(path):
            for line in open(path):
                k, _, v = line.strip().partition("=")
                if k.strip() == name:
                    return v.strip().strip("'\"")
        if os.path.dirname(d) == d:
            return None
        d = os.path.dirname(d)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="veil audit")
    p.add_argument("--driver", choices=["claude", "sdk", "openai", "codex"], default="claude")
    p.add_argument("--provider", choices=["anthropic", "bedrock", "vertex", "foundry", "anthropic-aws"], default="anthropic",
                   help="claude driver: which API format Claude Code speaks to veil")
    p.add_argument("--upstream", default="mock", help="'mock' (offline fake LLM) or an Anthropic-format base URL")
    p.add_argument("--api-key-env", default="ANTHROPIC_API_KEY")
    p.add_argument("--model", default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--max-turns", type=int, default=15)
    p.add_argument("--ner", action="store_true", help="enable the optional NER layer for free text")
    args = p.parse_args(argv)

    label = ("mock" if args.upstream == "mock" else (args.model or "upstream")) + ("_ner" if args.ner else "") \
        + ("" if args.provider == "anthropic" else f"_{args.provider}")
    out = os.path.abspath(args.out or os.path.join(ROOT, "captures", f"audit_{args.driver}_{label}"))
    veil, real_values, ws = scenario(out)
    if args.ner:
        from veil.ner import GlinerDetector
        veil.ner = GlinerDetector()
    mock = None
    if args.upstream == "mock" and args.provider in ("bedrock", "vertex"):
        mock = start_mock_cloud(db_path="chinook.sqlite")
        upstream, api_key = f"http://127.0.0.1:{mock.server_port}", "unused-cloud-auth-skipped"
    elif args.upstream == "mock" and args.driver == "codex":
        mock = start_mock_responses(db_path="chinook.sqlite")
        upstream, api_key = f"http://127.0.0.1:{mock.server_port}", "sk-mock-not-a-real-key"
    elif args.upstream == "mock":
        mock = start_mock_llm(db_path="chinook.sqlite")
        upstream, api_key = f"http://127.0.0.1:{mock.server_port}", "sk-ant-mock-not-a-real-key"
    else:
        upstream, api_key = args.upstream, _load_env_key(args.api_key_env)
        if not api_key:
            print(f"{args.api_key_env} not set (env or .env)", file=sys.stderr)
            return 2
    rec = Recorder()
    log = open(os.path.join(out, "veil.log"), "w")
    px = start_proxy(veil, upstream, rec, log=log)
    proxy_url = f"http://127.0.0.1:{px.server_port}"
    model = args.model or ("claude-opus-5-5" if args.driver == "sdk" else ("gpt-6" if args.driver == "openai" else None))
    print(f"[veil audit] {args.driver} -> veil -> {upstream} (model {model or 'default'})", file=sys.stderr)
    try:
        if args.driver == "sdk":
            final, executed = run_sdk(proxy_url, api_key, model, ws, args.max_turns)
        elif args.driver == "openai":
            final, executed = run_openai(proxy_url, api_key, model, ws, args.max_turns)
        elif args.driver == "codex":
            final, executed = run_codex(proxy_url, api_key, model, ws, args.max_turns)
        else:
            final, executed = run_claude(proxy_url, api_key, model, ws, args.max_turns, args.provider)
    finally:
        px.shutdown()
        if mock:
            mock.shutdown()
    summary = write_captures(out, veil, rec.exchanges, real_values,
                             f"What the LLM received — {args.driver} driver, upstream {label}")
    with open(os.path.join(out, "developer_view.txt"), "w") as f:
        f.write(final + "\n\n# tools executed locally (rehydrated)\n" + json.dumps(executed, ensure_ascii=False, indent=2))
    summary["report"] = os.path.relpath(os.path.join(out, "REPORT.md"))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\nFinal answer as the developer saw it (rehydrated):\n" + final[:2500])
    if summary["requests"] == 0:  # the client never reached veil: nothing was tested
        print("[veil audit] FAILED: the client made no model requests", file=sys.stderr)
        return 2
    return 1 if summary["leaks"] else 0


if __name__ == "__main__":
    sys.exit(main())
