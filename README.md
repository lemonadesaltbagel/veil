# veil

**Privacy middleware for AI coding agents.** The model sees consistent pseudonyms; your machine
keeps the real values.

```text
what the agent read locally          what the LLM receives                what you see in the answer
---------------------------          ---------------------                ---------------------------
Leonie Köhler                        First_Ttnx Last_Ttnx                 Leonie Köhler
leonekohler@surfeu.de                user_ttnx@example.test               leonekohler@surfeu.de
card=4111 1111 1111 1111             card=card_y2vb                       card=4111 1111 1111 1111
/Users/alice/code/shop               /Users/user_pjgu/code/shop           /Users/alice/code/shop
```

Coding agents send everything they read to the model provider: database query results, logs,
fixtures, stack traces, even your home-directory name. veil is a local proxy that pseudonymizes all
of it before it leaves your machine. Commands the agent runs get the real values back locally, so it
can still query your real dev database and fix real bugs.

> **Status: alpha.** It works end to end with Claude Code, Codex CLI and OpenAI-compatible clients,
> and it has been tested against real models. It hasn't been used in production yet. See
> [Limitations](#limitations).

## How it works

```text
 coding agent ──► veil (127.0.0.1:8787) ──► model provider
   (real data)    redact ▸ guard ▸ forward      (pseudonyms only)
              ◄── rehydrate per tool policy ◄──
```

- **Seeding (the core idea).** veil learns the real values from your own data sources: Postgres,
  MySQL/MariaDB, MongoDB, Redis, SQLite, and fixture files. It classifies fields from native PII
  labels, column and JSON-path names, and value sampling. It then matches those exact values wherever
  they appear (logs, free text, JSON, code). Regex and NER guess; seeding knows.
- **Coherent pseudonyms.** Pseudonyms are deterministic HMAC tokens. Everything about one person
  shares one code (`user_ab12`, `user_ab12+2@example.test`, `First_Ab12 Last_Ab12`, `Ab12 Example
  Street`), so the model can still reason about who is who. Because the same input always produces
  the same pseudonym, prompt caching keeps working (82–89% cache hits in real runs).
- **Per-tool restore policy.**
  - Shell, read and grep tools get real values back, escaped for the exact shell or SQL quoting
    context, so a stored `$(rm -rf ~)` stays data.
  - Edit and write tools may only restore values that already exist in the target file, so the agent
    can never write *new* real PII into your code.
  - Web tools, unknown tools and network-capable commands (`curl`, `ssh`, `git push`) never receive
    real values.
- **Outbound guard.** A final check scans every outgoing request, independently of the redaction
  step. It looks for every known value in plain, encoded (URL, base64, JSON escapes), transformed
  (reversed, rot13, upper-cased, spaced out, hex) and truncated forms. It repairs what it can and
  withholds or blocks the rest.
- **Encrypted local vault.** Real values are stored AES-256-GCM encrypted, with keys in the macOS
  Keychain or the Linux Secret Service.

## Supported clients

One proxy serves all of them, routed by path:

| Client | API | Point it at veil |
|---|---|---|
| Claude Code, Claude Agent SDK | Anthropic Messages | `veil init` (or `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`) |
| Claude Code on Amazon Bedrock | Bedrock InvokeModel (binary event stream) | `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_BEDROCK_BASE_URL=http://127.0.0.1:8787`, `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1` |
| Claude Code on Google Vertex | Vertex rawPredict | `CLAUDE_CODE_USE_VERTEX=1`, `ANTHROPIC_VERTEX_BASE_URL=http://127.0.0.1:8787/v1`, `CLAUDE_CODE_SKIP_VERTEX_AUTH=1` |
| Codex CLI | OpenAI Responses | provider with `base_url = "http://127.0.0.1:8787/v1"`, `wire_api = "responses"` |
| Aider, Continue, OpenAI SDK, LiteLLM | OpenAI Chat Completions | `OPENAI_BASE_URL=http://127.0.0.1:8787/v1` |

For Bedrock and Vertex, the client skips its own auth and veil signs requests *after* redacting
them. Bedrock uses `AWS_BEARER_TOKEN_BEDROCK` or SigV4 (`veil-proxy[bedrock]`); Vertex uses
`gcloud` or `VEIL_VERTEX_TOKEN`.

## Install

veil is published on **TestPyPI** as `veil-proxy`. It installs the `veil` and `veil-hook` commands.

```sh
# veil-proxy from TestPyPI, its dependencies from PyPI
pip install --no-deps -i https://test.pypi.org/simple/ veil-proxy
pip install httpx cryptography pyahocorasick
# database drivers are extras: veil-proxy[postgres], [mysql], [mongo], [redis], [bedrock], [ner], [all]
```

Or from source (requires [uv](https://docs.astral.sh/uv/)):

```sh
git clone <this repo> && cd veil/prototype
uv sync
uv run veil --help
```

## Quick start (Claude Code)

```sh
veil init ~/code/myapp        # finds DATABASE_URL / REDIS_URL / MONGODB_URI in .env*, SQLite files, fixtures/;
                              # seeds them; writes ~/code/myapp/.claude/settings.local.json (git-ignored)
veil service install          # proxy as a LaunchAgent (macOS) or systemd user unit (Linux)
veil status ~/code/myapp      # proxy, service, keys, vault, project wiring
cd ~/code/myapp && claude     # nothing else to configure
```

`veil init` merges into existing settings, never overwrites them, and is safe to re-run. It adds
veil's hooks as a second layer (≈40 ms per call via the running proxy).

**Verify it yourself:** `veil proxy --capture DIR` writes every request exactly as the model received
it (pseudonyms only).

Seed more sources at any time:

```sh
veil seed postgresql://user@localhost/app mysql://root@localhost/app redis://localhost:6379/0 \
          mongodb://localhost:27017/app ./fixtures
```

## Teams

```sh
veil team allow support@mycompany.com             # values that are never PII
veil team export --passphrase-env TEAM_PW         # pseudonym secret + allowlist (never the vault key)
veil team join <bundle> --passphrase-env TEAM_PW  # identical pseudonyms on every machine
veil team managed-settings --port 8787            # managed-settings.d/ drop-in that forces Claude Code through veil
```

The managed-settings file pins the proxy address and sets `allowedProviders: ["customEndpoint"]`, so
Claude Code accepts only that exact endpoint. It must be installed by an admin into
`/Library/Application Support/ClaudeCode/managed-settings.d/` (macOS) or
`/etc/claude-code/managed-settings.d/` (Linux).

## Testing

```sh
cd prototype
uv run pytest -q                          # unit + integration tests (DB tests skip when DBs are down)
scripts/fetch_datasets.sh                 # public sample data (Chinook, MongoDB mflix, Redis users, ai4privacy)
scripts/dev_dbs.sh start                  # local Postgres (Docker) + MariaDB/Redis/MongoDB (Homebrew)
uv run veil audit                         # real Claude Code -> veil -> scripted fake model; reports what the model saw
uv run veil audit --driver codex          # real Codex CLI, same idea (also: --provider bedrock|vertex, --driver openai|sdk)
uv run python -m veil.redteam             # 20 one-command bypass techniques (byte dumps, rev, rot13, hex(), cut...)
uv run python scripts/eval_ai4privacy.py  # free-text leak rates: patterns / +NER / seeded
```

Results from the development runs:

| Measurement | Result |
|---|---|
| Real Claude Code / OpenAI SDK sessions against DeepSeek | 0 leaks under a decoding leak scan; correct answers |
| Bypass matrix | 20 / 20 techniques contained |
| Free-text name/contact leak rate (1,000 labelled rows) | 80% patterns only → 17.6% with NER → **1.8% when seeded** |
| Overhead at ~40k seeded values | ≈ 8 ms redaction + 11 ms guard per 67k-character request |

## Limitations

- **Your machine is trusted.** The vault, the agent's local transcripts (which show real values) and
  local telemetry all hold real data.
- **Unanticipated transforms.** An agent with a shell can transform data in ways veil doesn't
  anticipate. veil blocks byte dumps and decodes 20 known transforms, but that's a tested matrix, not
  a proof.
- **Fragment searches.** A search on *part* of a pseudonym (`LIKE '%ab12%'`) can't match real data.
  veil explains this to the model instead of running the command.
- **Short values.** Seeded values shorter than 8 characters are only matched verbatim or encoded.
  Standalone first or last names that are common words (`Mark`, `Code`) aren't seeded on their own;
  the full name still is.
- **Free text about third parties** needs the optional NER model (`veil-proxy[ner]`, then
  `veil ner-model fetch`).
- **Re-identification.** Quasi-identifiers such as tenant names, rare values and timestamps can still
  allow re-identification.

## Repository layout

```text
docs/RESEARCH.md     landscape, interception points, findings from every test round, limitations
docs/DESIGN.md       architecture, token scheme, tool policy, guard, adapters, threat model
docs/DATABASES.md    seeding: implemented sources, classification signals, other database families
prototype/veil/      the package (proxy, engine, guard, seeders, API adapters, CLI)
prototype/tests/     test suite
prototype/scripts/   dev databases, dataset fetch, evaluation, Homebrew formula generator
```

## Acknowledgements

The column-name dictionary in `veil/data/` is from
[PostgreSQL Anonymizer](https://gitlab.com/dalibo/postgresql_anonymizer) (PostgreSQL License). Test
data comes from the [Chinook database](https://github.com/lerocha/chinook-database), the
[MongoDB sample datasets](https://github.com/neelabalan/mongodb-sample-dataset),
[redis-datasets](https://github.com/redis-developer/redis-datasets) and
[ai4privacy](https://huggingface.co/datasets/ai4privacy/pii-masking-200k). These are downloaded by
`scripts/fetch_datasets.sh`, not redistributed.

## License

No license has been chosen yet.
