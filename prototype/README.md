# veil

Privacy middleware for AI coding agents. The model sees consistent pseudonyms
(`user_ab12@example.test`, `First_Ab12 Last_Ab12`); your machine keeps the real values,
and commands the agent runs locally get the real values back (shell- and SQL-safe).

```sh
pip install "veil-proxy[postgres]"    # extras: postgres, mysql, mongo, redis, bedrock, ner, mssql, snowflake, all
                                      # (installs the `veil` and `veil-hook` commands; import name `veil`)
veil init ~/code/myapp                # seed from .env DB URLs, SQLite, fixtures; wire Claude Code
veil service install                  # proxy as a LaunchAgent (macOS) / systemd user unit (Linux) / Startup item (Windows)
veil status ~/code/myapp
```

Evidence from our own test runs (details and the harness to re-run them are on GitHub:
https://github.com/lemonadesaltbagel/veil):

- 39 requests from real agent sessions against a live model leaked **0** real values (checked with
  a scanner that also decodes escaped and transformed text), and every session still found the bug.
- Seeding from your own data lets **1.8%** of names and contact details through, versus 80.4% for
  pattern matching (1,000 labelled records).
- **21/21** one-command bypass transforms are contained. Restored values are escaped for every
  language layer they pass through (shell, heredocs, `python -c`, `node -e`, SQL, `bash -c`...):
  35/35 injection tests, and 68,000 fuzzed nested commands executed with 0 code executions.
- Prompt caching keeps working (74–89% cache hits); about 19 ms overhead per request at 40k seeded
  values, and 37 + 68 ms per 234 KB request at 1.2 million seeded values (1.1 GB).

One local proxy (default `127.0.0.1:8787`) serves every client, routed by path:
Anthropic Messages (Claude Code, Agent SDK), Amazon Bedrock InvokeModel (binary eventstream),
Google Vertex rawPredict, Microsoft Foundry (`/foundry`), Claude Platform on AWS (`/anthropic-aws`),
OpenAI Chat Completions (Aider, Continue, OpenAI SDK) and OpenAI Responses (Codex CLI).
DeepSeek Harness uses the [dsh-veil](https://github.com/lemonadesaltbagel/dsh-veil) plugin. Other
agents' tools can get veil's restore rules with `veil proxy --tool-alias NAME=ROLE`.

Seeds from Postgres, MySQL/MariaDB, SQLite, SQL Server (native sensitivity labels), MongoDB, Redis,
Elasticsearch/OpenSearch and fixture files, plus personal fields declared in code (Prisma, Django,
Rails, SQLAlchemy, OpenAPI, protobuf), and re-seeds automatically when the data changes.

Also seeds git history, DynamoDB (personal data inside keys), Snowflake and BigQuery (their privacy
tags). `veil mcp-db` gives the agent a read-only database tool in which pseudonyms become **bound
parameters**, so real values are never SQL text.

```sh
veil init ~/code/myapp --mcp   # also register the database tool with Claude Code
veil display tokens        # screen sharing: answers keep pseudonyms (veil display real to undo)
veil quasi redact          # also pseudonymise rare cities, postal codes, birth dates, employers
veil keys rotate           # re-encrypt the vault; --token-secret for new pseudonyms
```

Teams: `veil team export | join` shares the pseudonym secret (never the vault key);
`veil team managed-settings` writes a Claude Code `managed-settings.d/` drop-in that pins the
proxy with `allowedProviders: ["customEndpoint"]`.

Optional NER for free text: `pip install "veil-proxy[ner]"` then `veil ner-model fetch`.

License: Apache-2.0. Status: alpha. Keys: macOS Keychain / Linux Secret Service (`secret-tool`) / Windows Credential
Manager, or `VEIL_VAULT_KEY` / `VEIL_TOKEN_SECRET` (base64). State: `~/.veil` (encrypted vault).
