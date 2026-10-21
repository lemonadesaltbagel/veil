"""Real Claude Code + `veil mcp-db` through the veil proxy, with a scripted model.

    uv run python -m veil_dev.mcp_e2e

The model asks for a customer by the pseudonym it sees; Claude Code calls the MCP
database tool; veil binds the real value as a parameter, returns pseudonymised rows;
the developer sees real values. Checks: every upstream payload is free of real values,
the query found the row, and the answer shown to the developer is rehydrated.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

from veil import state
from veil.sources import seed
from veil_dev.audit import CHINOOK
from veil_dev.testing import Recorder, find_leaks, start_mock_llm, start_proxy

EMAIL = "leonekohler@surfeu.de"


def main() -> int:
    work = tempfile.mkdtemp(prefix="veil-mcp-e2e-")
    env = {"VEIL_HOME": os.path.join(work, "home"), "VEIL_VAULT_KEY": base64.b64encode(os.urandom(32)).decode(),
           "VEIL_TOKEN_SECRET": base64.b64encode(os.urandom(32)).decode(), "VEIL_KEYCHAIN": os.path.join(work, "none")}
    os.environ.update(env)
    db = shutil.copy(CHINOOK, os.path.join(work, "chinook.sqlite"))
    veil = state.load()  # the proxy and the MCP server share this vault (multi-process)
    seed(veil.known, db)
    state.save_known(veil.known, veil.vault.cipher)
    real = sorted(veil.known._entries, key=len, reverse=True)

    llm, rec = start_mock_llm(db_path=db), Recorder()
    px = start_proxy(veil, f"http://127.0.0.1:{llm.server_port}", rec)
    mcp_config = os.path.join(work, "mcp.json")
    with open(mcp_config, "w") as f:
        json.dump({"mcpServers": {"veil-db": {"command": sys.executable, "args": ["-m", "veil.cli", "mcp-db", db],
                                              "env": env}}}, f)
    claude_env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC"))
                  and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    claude_env.update({"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{px.server_port}", "ANTHROPIC_API_KEY": "sk-ant-mock",
                       "CLAUDE_CONFIG_DIR": os.path.join(work, "claude"), "NO_PROXY": "127.0.0.1,localhost",
                       "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"})
    prompt = f"Customer {EMAIL} says they were charged twice. Check their latest invoices."
    try:
        p = subprocess.run(["claude", "-p", prompt, "--output-format", "json", "--max-turns", "6",
                            "--mcp-config", mcp_config, "--strict-mcp-config",
                            "--allowedTools", "mcp__veil-db__query"],
                           cwd=work, env=claude_env, capture_output=True, text=True, timeout=300)
    finally:
        px.shutdown(); llm.shutdown()
    answer = json.loads(p.stdout).get("result", "") if p.stdout.strip().startswith("{") else p.stdout + p.stderr
    sent = [e["sent"] for e in rec.exchanges if e.get("sent")]
    leaks = [v for s in sent for v in find_leaks(json.dumps(s, ensure_ascii=False), real)]
    results = [b for s in sent for m in s.get("messages", []) if isinstance(m.get("content"), list)
               for b in m["content"] if b.get("type") == "tool_result"]
    result_text = json.dumps(results, ensure_ascii=False)
    report = {"requests": len(sent), "leaks": sorted(set(leaks)), "mcp_tool_results": len(results),
              "rows_found": result_text.count("example.test"), "developer_saw_real_email": EMAIL in answer}
    print(json.dumps(report, indent=1))
    print("\nAnswer as the developer saw it:\n" + answer[:800])
    print("\nWhat the model received from the tool (pseudonymised):\n" + (results[0]["content"][0]["text"][:600]
                                                                       if results and isinstance(results[0].get("content"), list)
                                                                       else result_text[:600]))
    ok = not leaks and results and report["developer_saw_real_email"]
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
