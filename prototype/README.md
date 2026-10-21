# veil

Privacy middleware for AI coding agents. The model sees consistent pseudonyms
(`user_ab12@example.test`, `First_Ab12 Last_Ab12`); your machine keeps the real values,
and commands the agent runs locally get the real values back (shell- and SQL-safe).

```sh
pip install "veil-proxy[postgres]"    # extras: postgres, mysql, mongo, redis, bedrock, ner, all
                                      # (installs the `veil` and `veil-hook` commands; import name `veil`)
veil init ~/code/myapp                # seed from .env DB URLs, SQLite, fixtures; wire Claude Code
veil service install                  # proxy as a LaunchAgent (macOS) / systemd user unit (Linux)
veil status ~/code/myapp
```

Evidence from our own test runs (details and the harness to re-run them are on GitHub:
https://github.com/lemonadesaltbagel/veil):

- 39 requests from real agent sessions against a live model leaked **0** real values (checked with
  a scanner that also decodes escaped and transformed text), and every session still found the bug.
- Seeding from your own data lets **1.8%** of names and contact details through, versus 80.4% for
  pattern matching (1,000 labelled records).
- **20/20** one-command bypass transforms are contained, and restored values are escaped for their
  shell/SQL context (35/35 injection tests).
- Prompt caching keeps working (74–89% cache hits); about 19 ms overhead per request at 40k seeded
  values.

One local proxy (default `127.0.0.1:8787`) serves every client, routed by path:
Anthropic Messages (Claude Code, Agent SDK), Amazon Bedrock InvokeModel (binary eventstream),
Google Vertex rawPredict, OpenAI Chat Completions (Aider, Continue, OpenAI SDK) and
OpenAI Responses (Codex CLI).

Teams: `veil team export | join` shares the pseudonym secret (never the vault key);
`veil team managed-settings` writes a Claude Code `managed-settings.d/` drop-in that pins the
proxy with `allowedProviders: ["customEndpoint"]`.

Optional NER for free text: `pip install "veil-proxy[ner]"` then `veil ner-model fetch`.

Status: alpha. Keys: macOS Keychain / Linux Secret Service (`secret-tool`), or `VEIL_VAULT_KEY` /
`VEIL_TOKEN_SECRET` (base64). State: `~/.veil` (encrypted vault).
