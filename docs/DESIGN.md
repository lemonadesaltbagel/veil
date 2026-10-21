# Veil — Design

## Goal

The LLM sees a consistent fake world; the developer's machine keeps the real one.

```
                    real world                    │              fake world
                                                  │
  Postgres / SQLite ──seed──▶ ┌──────────────┐    │
  CSV, fixtures               │  Vault       │    │
                              │ value⇄token  │    │
                              └──────┬───────┘    │
                                     │            │
  Claude Code ──request (real)──▶ ┌──┴─────────┐ ─┼─ request (tokens) ──▶  api.anthropic.com
  (tools run   ◀─response (real)─ │ veil proxy │ ◀┼─ response (tokens) ──
   locally)                       └────────────┘  │
       ▲  PreToolUse: token→real (policy)         │
       └─ PostToolUse: real→token  (defence in depth, optional)
```

## Layers (defence in depth)

| # | Layer | Role | Fails |
|---|---|---|---|
| 0 | **Source** — masked DB role (pg_anonymizer) or masked dev copy | Best when the agent never needs real values | closed |
| 1 | **Proxy** — `ANTHROPIC_BASE_URL` (enforce with managed `allowedProviders`) | Enforcement: sees all context, both directions | closed |
| 2 | **Hooks** — PostToolUse redact / PreToolUse rehydrate | Backup; and for setups without a proxy | open |
| 3 | **Deny rules / sandbox** — raw dumps, `.env`, `data/` | Remove what never needs to be read | closed |

## Core engine

### Tokens
- `code = base32(HMAC‑SHA256(secret, group or kind‖value))[:4]`, alphabet without look‑alikes.
  - Deterministic → the same value always gets the same token → **byte‑stable history → prompt cache hits**.
  - Keyed → the provider can't dictionary‑attack tokens back to emails (unlike plain hashes).
  - Team‑shared `secret` → identical tokens on every machine → shareable bug reports ("user_cq5f fails").
  - Collision → retry with `#attempt` and widen the code; vault enforces uniqueness.
- **Format‑preserving, obviously‑fake renderings** so validators/tests keep working:

  | kind | token |
  |---|---|
  | username | `user_cq5f` |
  | email | `user_cq5f@example.test` (RFC 6761 reserved) |
  | name / first / last | `First_Cq5f Last_Cq5f` / `First_Cq5f` / `Last_Cq5f` (full = first + " " + last) |
  | 2nd value, same person | `user_cq5f_2`, `user_cq5f+2@example.test`, `Cq5f Example Street 2` |
  | phone | `+1-270-555-0131` (NANP fictional 555‑01xx) |
  | ipv4 | `203.0.113.196` (RFC 5737 documentation ranges) |
  | card / secret / other | `card_dusn`, `secret_x7k2`, `<kind>_<code>` |
- **Row grouping**: values seeded from the same record share the HMAC material (`users:42`), so one
  person gets one code across all their fields.
- Avoid `<PERSON_1>` / `[REDACTED_…]` (markdown/HTML mangling, tokenizer splits, ordinal instability).

### Detection (priority order; overlaps → longest span, then priority)
1. **Known values** — exact dictionary seeded from data sources (column classifier: `email`,
   `username|login|handle`, `first_name`, `name` only on person‑like tables, `phone`, `ip`…).
   Identifier boundaries so `alice_w` ≠ `malice_wrapper`. Min length + stopword list for short values.
   Aho–Corasick over each needle's first 6 characters, confirmed by set lookups of the candidate
   lengths: 1.2M seeded values cost 1.1 GB and ~37 ms per 234 KB request (`docs/SCALE.md`).
2. **Patterns** — email, phone (separator required), public IPv4 only, cards (Luhn), secrets
   (AWS, `sk-`, `ghp_`, Slack, JWT). Production: adopt a checksum‑validated, false‑positive‑tested set.
3. **NER (optional, `veil[ner]`, `--ner`)** — GLiNER-PII edge (46 MB quantised ONNX, ~15 ms/row) on free
   text only (messages, tool results), never system prompts/tool schemas/`<system-reminder>`s; labels
   person/email/phone/address only; product-name allowlist; cached per string (deterministic, cache-safe);
   its guesses never become guard needles.
- Allowlist reserved domains (`example.com`, `*.test`, `*.invalid`), private/loopback IPs.
- **Existing tokens are never re‑redacted** (idempotency; required for history stability).

### Vault (encrypted)
SQLite under `~/.veil` (0600), schema v2: real values and groups AES-256-GCM-encrypted, each bound to
its token as associated data (rows can't be swapped); rows found by a keyed hash of (kind, value);
`known.enc` holds the encrypted seed dictionary. Two keys in the macOS Keychain (service `veil`):
`vault-key` (never leaves the machine) and `token-secret` (share it for team-identical tokens).
`VEIL_VAULT_KEY` / `VEIL_TOKEN_SECRET` env for CI/Linux; 0600 key files as a warned fallback.
Keychain items are created via `security -i` on stdin (keys never in argv/`ps`). v1 plaintext state
is migrated and `VACUUM`ed. Tampering or a wrong key fails closed (`InvalidTag`).

## Proxy transforms (Anthropic Messages)

**Request (machine → model):** **default-deny** — redact every string in every top-level field
except pure config (`model`, `max_tokens`, `stream`, `thinking`, `tool_choice`, `output_config`, …).
Claude Code sends PII outside `system`/`messages` (e.g. `safeguards[].classifier_context.home_dir`).
Inside `system`/`messages`: `text`, `tool_result`, assistant `tool_use.input`, documents, unknown blocks. Leave
`thinking`/`redacted_thinking` (signed; only ever contain tokens) and images untouched. Don't touch
headers or non‑content fields. Because we rehydrated tool inputs on a previous turn, Claude Code sends
real values back in history; re‑redaction maps them to the *same* tokens → identical bytes.

**Outbound guard (after redaction, before forwarding):** structure-blind second pass over every
string in the final body: all real values veil knows, in plain + encoded forms (URL, JSON `\u`,
NFD; base64 runs decoded at every alignment), plus pattern PII. Repairs in place (value → token); a hit inside a
signed thinking block can't be repaired → request blocked (`400`, `x-should-retry: false`). Audit
lines carry field path, kind and token, never the value. Exists because both mock-test leaks were
"didn't look there" bugs.

**Escaped output:** the guard also checks decoded views of each string (line continuations, sed `l`
`$` markers, octal / `\x` / `\u` escapes); a real value visible only after decoding means the whole
string is withheld (`[veil: output withheld …]`). Byte-dump commands are not run at all (below).
Real values inside model-written thinking are reported but allowed: the provider wrote them, and
signed blocks can't be edited — such a hit means an earlier leak to investigate.

**Pseudonym notice:** agent requests get one static system block telling the model pseudonyms are
opaque and must be used whole (real models grep/LIKE on token fragments). Static text keeps caching intact.

**Matching:** Aho–Corasick over 6-character anchors for known values, guard needles and tokens
(Python `re` alternation of thousands of literals cost ~400 ms per Claude Code request). Known emails
match case-insensitively. 1.2M seeded values: 1.1 GB, 37 + 68 ms per 234 KB request (`docs/SCALE.md`).

**Rehydrating into commands (data → code boundary):** a real value put into a Bash command is
escaped for every language layer it passes through, innermost first (`veil/shell.py`):

1. **Embedded language.** The shell word or heredoc is code for an interpreter:
   - `python -c`, including f-strings (braces doubled), raw strings (no quote or backslash fits:
     the token stays) and bytes;
   - `node -e` (template literals: `${` escaped), `ruby -e` (`#{`), `perl -e` (`$`, `@`), `php -r`,
     `jq`, `awk`, `mongosh --eval`;
   - SQL clients, including `sqlite3 db "…"`, `psql -c`, `mysql -e` (backslashes too) and heredocs
     fed to them;
   - `bash -c` and `eval`, handled recursively.

   The value is escaped for the string literal it sits in. A token in *code* position is restored
   only if the value is inert there (letters, digits, `_.@+-`).
2. **Shell quoting at that spot.** Unquoted, `'…'`, `"…"`, `$'…'`, backticks (inert values only),
   `$( … )` (a fresh context), and heredoc bodies: a quoted delimiter is literal; an unquoted one makes
   `\ $ `` ` `` special, and a value containing a newline could end the body.
3. **Where the value's output becomes code, only inert values are restored.** That covers a
   substitution in command position (`$(printf %s X)`), output piped into an interpreter or into
   `xargs -I`/`xargs sh`, and values reaching code through variables (`v=X; python3 -c "…$v…"`).
   Values piped into an SQL client inside an SQL literal are SQL-escaped instead.

When no safe spelling exists, the pseudonym stays in the command: it finds nothing rather than
running something nobody wrote. Evidence:

- 35 shell/SQL injection tests (23 fail without this);
- 30 embedded contexts × 15 hostile values, really executed;
- 50,000 fuzzed nestings, really executed (`python -m veil_dev.shellfuzz`), with 0 executions.

**Bypass matrix (`python -m veil_dev.redteam`, regression-tested):** 21 one-command transforms an agent can
apply (octal/hex/base64 dumps, repr/JSON escapes, rev, rot13, upper-casing, one char per line, spaced
letters, `cut` mid-value or mid-character, SQL `hex()`/`upper()`/`replace()`/`substr()`/`unicode()`, URL-encoding). All 20
contained (all 21 now): byte dumps blocked by command policy; the guard withholds message content whose
case/space/reversal/rot13/hex/URL/escape-normalised view contains a seeded value of ≥ 8 chars, replaces
value heads/tails cut at line boundaries with `[veil:partial]`, and seeds email local parts as their own
values (`leonekohler at surfeu dot de`). The audit oracle decodes all of these (plus char codes) —
an earlier oracle without them reported 15/20 when the truth was 9/20.

**Scale (≈ 40k seeded values from 4 stores):** redaction ≈ 8 ms, guard ≈ 11 ms per 67k-char Claude Code
request; guard index split into a seeded part (built once, 0.5 s) and a small pattern-found part.
Standalone first/last names and usernames that are lower-case dictionary words (`Code`, `Read`, `Mark`)
are not seeded alone (they rewrote "Claude Code" and the `Read` tool name); full names still are. The
guard never touches structural keys (`type`, `id`, tool names) and runs its heuristics only on messages.

**Response (model → machine):**
- `tool_use.input` → rehydrated per **sink policy**:

  | mode | tools | behaviour |
  |---|---|---|
  | full | Bash, Read, Grep, Glob, allowlisted MCP (e.g. DB) | all tokens → real |
  | preserve | Edit, MultiEdit, Write, NotebookEdit | locators (`file_path`, `old_string`) fully; content (`new_string`, `content`) only tokens whose real value **already exists in the target file** → new PII is never written into source/fixtures |
  | none | WebFetch, WebSearch, Agent, unknown tools; **Bash commands with egress** (curl, wget, ssh, git push…) | tokens stay tokens (fail‑safe; blocks prompt‑injection exfiltration of real data) |
  | notice | Bash using a **pseudonym fragment** (`LIKE '%ab12%'`) or a **byte dump** (`sed l`, `od`, `xxd`, `cat -v`, `base64`) | command replaced by an `echo` explaining why (fragments: cites the person's real tokens); Grep-tool fragments are expanded to the person's real values instead |
- assistant `text` → rehydrated for display (configurable `--show-tokens`).
- **Streaming**: text deltas are rehydrated with a hold‑back buffer of `max_token_len` chars (tokens
  split across deltas are restored; matching sees real neighbours on both sides); `input_json_delta`
  is buffered until `content_block_stop`, rehydrated as parsed JSON (correct escaping), emitted as one
  delta; pings/thinking/signatures/usage pass through immediately.
- `count_tokens`: request redacted, response passed through. Errors: bodies forwarded unmodified.
- Any redaction failure → 502, never forward raw.

## OpenAI-format adapters (same lens)

- **Chat Completions** (`/chat/completions`, `/v1/chat/completions`): message text/parts, tool results,
  assistant `tool_calls[].function.arguments` (a JSON *string*: parsed, redacted, re-serialised); `user`
  and unknown fields default-deny; notice inserted after the leading system messages (stable prefix).
  Streams: text via the shared hold-back (`stream.TextHold`); tool-call argument deltas buffered per call
  until `finish_reason`, then emitted whole after policy.
- **Responses** (`/v1/responses`, Codex): `instructions`, message items, `function_call` arguments,
  `function_call_output`, `custom_tool_call` (`apply_patch` → preserve over the files it touches; header
  paths made real), `local_shell_call`; **`reasoning` items (encrypted) untouched**. Streams: deltas,
  `*.done`, `output_item.done` and `response.completed` are rewritten consistently (one rehydration per item).
- Tool names are arbitrary in this world, so sinks are classified by name: shell/exec/terminal → Bash
  policy (string, `cmd`, or argv `["bash","-lc",script]`; plain argv gets substitution without escaping);
  read/search → full; write/edit/patch → preserve; `write_stdin` (keystrokes into a possibly-shell
  session) and unknown tools → no real values.

## Adoption

- `veil init PROJECT`: detects `*_DATABASE_URL`/`REDIS_URL`/`MONGODB_URI`… in `.env*`, SQLite files,
  fixtures/seeds dirs; seeds them (credentials masked in output); writes project-local
  `.claude/settings.local.json` (merged, idempotent, git-ignored): `env.ANTHROPIC_BASE_URL`, `NO_PROXY`,
  PreToolUse/PostToolUse veil hooks (absolute interpreter path); optional `--deny-env`.
- `veil service install|uninstall|status`: LaunchAgent `dev.veil.proxy` (RunAtLoad, KeepAlive), waits out
  `launchctl bootout`'s asynchrony before `bootstrap` (a real race we hit). `veil status` and
  `GET /veil/health` (counts only, never values).
- **Multi-process vault:** hooks and the long-running proxy share one SQLite vault (WAL). Each process
  loads rows added by others (`refresh()` by rowid) before allocating, on lookup misses, and at the start
  of every proxied request; allocation conflicts surface as `IntegrityError` and are retried. (Before this,
  a hook-allocated `card_…` token reached the developer un-rehydrated.)
- Hook latency ≈ 0.26 s per call with a 33k-value vault (fresh process); a future option is hooks that ask
  the running proxy instead.

## Cloud providers (Bedrock, Vertex)

Both carry Anthropic Messages bodies (+ `anthropic_version`, `anthropic_beta` body fields, passed as
config), so redaction is unchanged. Routing by path: Bedrock `/model/{id}/invoke[-with-response-stream]`,
`/count-tokens`; Vertex `.../publishers/anthropic/models/{m}:streamRawPredict|:rawPredict`.
Vertex streams SSE (existing StreamRewriter). **Bedrock streams binary
`application/vnd.amazon.eventstream`**: veil decodes frames (prelude/headers/payload, CRC32 checked),
rewrites the Anthropic event inside `{"bytes": base64(...)}`, re-encodes with fresh CRCs (validated
against botocore's decoder; real Claude Code parses it). Auth: clients skip their own signing
(`CLAUDE_CODE_SKIP_BEDROCK_AUTH` / `_VERTEX_AUTH`) and veil injects credentials **after** redaction —
a client SigV4 signature covers the body veil must change. Bedrock: `AWS_BEARER_TOKEN_BEDROCK` or SigV4
(botocore default credential chain); Vertex: `VEIL_VERTEX_TOKEN` or `gcloud auth print-access-token`.

**Microsoft Foundry and Claude Platform on AWS** carry plain Anthropic Messages under a path prefix:
`ANTHROPIC_FOUNDRY_BASE_URL=…/foundry` and `ANTHROPIC_AWS_BASE_URL=…/anthropic-aws`. veil strips the
prefix and forwards to `--foundry-upstream` / `--anthropic-aws-upstream`.

- Credentials that don't cover the body pass through: Foundry `x-api-key` and Entra bearer tokens,
  and the AWS workspace `x-api-key`.
- With the client's skip-auth flag, veil adds them itself: `ANTHROPIC_FOUNDRY_API_KEY` or an `az`
  token for Foundry, or a SigV4 signature over the *redacted* body for AWS. The service name comes
  from the host (`aws-external-anthropic`), since it is undocumented, and can be overridden.
- `anthropic-workspace-id` is forwarded unchanged.

Verified with real Claude Code 2.1.285 in both modes through veil (0 leaks, `veil audit --provider
foundry|anthropic-aws`).

## Teams

- `veil team export|join`: bundle = token secret + allowlist (scrypt + AES-GCM under a passphrase);
  the vault key never leaves a machine. Joining over a non-empty vault requires `--reset-vault`
  (tokens are re-derived deterministically from the new secret).
- `veil team allow`: team allowlist (values never treated as PII), applied to seeding and detection.
- `veil team managed-settings`: `managed-settings.d/50-veil.json` with managed `env.ANTHROPIC_BASE_URL`
  pinned + `allowedProviders: ["customEndpoint"]` (Claude Code admits only that exact endpoint;
  v2.1.285+), optional veil hooks via the stable `veil-hook` command, optional `allowManagedHooksOnly`.
  Installed by an admin into `/Library/Application Support/ClaudeCode/` or `/etc/claude-code/`.

## Display modes

What the developer sees is separate from what the model sees (always pseudonyms).

- `real` (default): responses and tool inputs are rehydrated, so the terminal shows real values.
- `tokens`: responses keep pseudonyms (screen sharing, demos, pairing). Tool inputs are still
  rehydrated, so commands keep working.

Resolution per request: an `x-veil-display: tokens` header (set through managed
`ANTHROPIC_CUSTOM_HEADERS` by `veil team managed-settings --display tokens`) or a `--show-tokens`
proxy forces tokens; otherwise `VEIL_DISPLAY`, then `display` in `~/.veil/config.json` (switched at
runtime by `veil display real|tokens`, no restart). A header can only make the display *stricter*,
and it is stripped before forwarding. `veil reveal FILE` and `veil share FILE` convert copied text
locally in either direction.

## Re-seeding

`veil seed` and `veil init` remember their sources (encrypted, `sources.enc`: URLs can carry
passwords; `veil sources` lists or removes them). While the proxy runs, a thread checks a cheap
fingerprint of each source every 30 s. The fingerprints are:

- Postgres: `pg_stat_user_tables` write counters;
- MySQL: `information_schema.TABLES` (stats cache disabled);
- Redis: `dbsize` + changes since save;
- MongoDB: `serverStatus` op counters (document counts as a fallback);
- files: mtime/size, including SQLite `-wal`.

On a change, the thread re-seeds the source into a copy of the known values, builds the matcher and
guard indexes, and swaps the copy in atomically. A request never waits for a rebuild; that took 94 s
at 1.2M values before the indexes were moved to the thread. Unreachable sources keep their last
snapshot. The interval stretches to 10× the last re-seed's duration.

A value redacted *before* it was seeded keeps its first token: stability, which keeps prompt caching
and the conversation consistent, wins over regrouping it with its person.

## Quasi-identifiers and direct identifiers

- **Direct identifiers** are always pseudonymised (`id_number_ab12`): columns named for SSNs,
  passports, national or tax IDs, driver's licences, IBANs and similar, plus SSN and IBAN patterns
  (the IBAN's mod-97 checksum is validated).
- **Quasi-identifiers** are the birth date, postal code, city, company and job title of person
  records. Date columns are read only when named for a birth date. Each value is seeded with the
  number of records sharing it, and only *rare* values (shared by fewer than 5 records) are
  considered: "London" identifies nobody, a 5-digit postal code with one customer does.
- `veil quasi warn` (the default) logs each request that newly carries rare quasi-identifiers. The
  log line gives kinds and counts, never values, and flags a person with two or more kinds together.
  Each value is reported once per proxy run.
- `veil quasi redact` pseudonymises them (`city_ab12`, `dob_ab12`) without the person's code, so
  three people who share a city are not linked to each other. `veil quasi off` disables both.

## Keys and rotation

- `veil keys rotate` replaces the vault key: the vault, retired tokens, `known.enc` and `sources.enc`
  are re-encrypted, and pseudonyms don't change. The sequence is crash-safe:
  1. A marker file is written and the new key is stored as `vault-key-next`.
  2. Every row is read with whichever key opens it, and the files are swapped in.
  3. The new key replaces `vault-key`.

  `state.load()` finishes a rotation that was interrupted between these steps. It refuses while a
  proxy is running, since the proxy would keep writing to the replaced file.
- `veil keys rotate --token-secret` issues new pseudonyms, after a suspected leak of the secret or a
  team change. Old tokens are *retired*: they still rehydrate, so conversations in flight keep
  working, but they are never issued again. `--drop-old` forgets them. Teams then re-export the
  bundle.

## Per-project vaults

Each project can get its own vault, keys, port and service:

```sh
VEIL_HOME=~/.veil-acme veil init ~/code/acme --port 8788
VEIL_HOME=~/.veil-acme VEIL_SERVICE_LABEL=dev.veil.acme veil service install --port 8788
```

The project's hook commands carry `--port 8788 --home ~/.veil-acme`. Before this, a hook fell back to
the default vault whenever the per-project proxy rejected its secret, which mixed two projects'
values.

## Fast hooks

`veil-hook pre|post` (stdlib only) forwards the hook event to the running proxy's
`/veil/hook/{pre,post}`: 39 ms vs 278 ms for an in-process hook with a 33k-value vault; falls back to
in-process when the proxy is down. The endpoint can rehydrate tokens, so it requires a per-install
secret (`~/.veil/hook.secret`, 0600, created at proxy start) and a loopback `Host` (DNS-rebinding guard).

## Linux

Keys in the Secret Service via `secret-tool` (secret on stdin); `veil service` writes a hardened
systemd user unit (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only` +
`ReadWritePaths=$VEIL_HOME`, 0600) and enables it with `systemctl --user`. Verified in a Debian
container: pip-installed wheel, GNOME Keyring via `dbus-run-session`, `systemd-analyze verify`.

## Windows

- **Keys** live in the Windows Credential Manager (ctypes `CredWriteW`/`CredReadW`, targets
  `veil:<name>`).
- **`veil service install`** writes a VBScript launcher to the user's Startup folder and starts the
  proxy at once, hidden and without admin rights (a scheduled task at logon usually needs them).
  `--pid-file` lets `uninstall` stop it. Keys from the environment are never written into the
  launcher.
- **Hook commands** quote interpreter paths with backslashes, because Git Bash would eat them.

The test suite runs on `windows-latest` in CI.

## Packaging

Distribution `veil-proxy` on PyPI. Core deps: httpx, cryptography, pyahocorasick. Extras: `postgres`,
`mysql`, `mongo`, `redis`, `bedrock`, `ner`, `all`. Console scripts `veil`, `veil-hook`. Build backend
`flit_core` (pure Python): Homebrew builds from source, and `uv_build`'s own source build needs maturin
plus a Rust toolchain. Only `veil/` is packaged; the dev harness lives in `veil_dev/`. The Homebrew
formula (tap `lemonadesaltbagel/homebrew-veil`) is generated from `uv.lock` plus the PyPI sdist
(`scripts/gen_brew_formula.py`). It depends on Homebrew's `cryptography` and on a matching
`python@3.x`, since that formula is only built for some Python versions. A `service do` block provides
`brew services`.

## Hook mode
`veil hook post` → `updatedToolOutput` with every string redacted (keeps the tool's output shape).
`veil hook pre` → `updatedInput` rehydrated with the same sink policy. Cannot cover the user prompt or
system prompt, and fails open on schema mismatch → backup only.

```json
{ "hooks": {
  "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "veil hook pre"  }] }],
  "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "veil hook post" }] }]
}}
```

## Threat model

- **Protects against:** provider‑side retention/logging/training exposure, transcripts shared with
  vendors, accidental leakage in prompts, prompt‑injected exfiltration via rehydrated web/egress calls.
- **Does not protect against:** a compromised local machine; real values in Claude Code's local
  transcript (rehydrated display); OTel/analytics that capture tool output before hooks
  (set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`); re‑identification through combinations of common
  values (rare quasi-identifiers are reported or pseudonymised); PII in images (out of scope: a
  developer who wants to leak a screenshot can); encoded forms not yet decoded.

## Roadmap

1. **MVP (prototype exists):** proxy + engine + SQLite seeding + hooks + tests. ✅
1b. **Outbound guard, encoded forms, `veil audit`, real-model run (DeepSeek), Aho–Corasick.** ✅
1d. **Hardening:** encrypted vault + Keychain, context-aware shell/SQL rehydration, bypass matrix
    20/20, scale fixes (dictionary-word filter, structural keys, split guard index). ✅
1c. **Seeders** (SQLite, Postgres, MySQL/MariaDB, MongoDB, Redis, fixture files, env), native labels,
    pg_anonymizer dictionary, FK/value grouping, fragment handling, optional NER, escape/byte-dump defence. ✅
    See `docs/DATABASES.md`.
2. ✅ SQL Server (native classifications), schema-from-code, Elasticsearch, continuous re-seeding
   (2026-10-21). Still to do: DynamoDB key segments, warehouses, `git log` authors.
3. ✅ Leak harnesses: `veil audit` (canary scenario, real agents, offline), bypass matrix
   (`veil_dev.redteam`), pilot on a real repository (`veil_dev.pilot`), CI with live databases.
4. ✅ done (see 1d). ✅ Per-project vaults, key rotation (2026-10-21). Still open: team secret distribution
   beyond a shared bundle.
5. ✅ Optional NER layer (GLiNER) for free text; ✅ quasi‑identifier warnings / redaction (2026-10-21).
6. ✅ OpenAI Chat Completions + Responses adapters (Aider/Continue/SDK; Codex). Still open: Bedrock/Vertex
   formats; MCP DB server with masking.
7. ✅ `veil init` / `status` / `service`; ✅ team mode, managed-settings drop-in, Linux (systemd + Secret
   Service), Bedrock/Vertex, fast hooks, packaging (2026-10-20).
8. ✅ Released: `veil-proxy` 0.1.1 / 0.1.2 on PyPI, Homebrew tap. ✅ Display modes, re-seeding, pilot,
   CI, scale to 1M values, Windows, Microsoft Foundry / Claude Platform on AWS, SQL Server and
   Elasticsearch seeders, schema hints from code (2026-10-21). Open: real-cloud runs (needs
   AWS/GCP/Azure accounts), DynamoDB and warehouse seeders.

## Open questions

- Should file writes ever get *new* real values (e.g. user explicitly asks to add a real admin email)?
  Proposed: explicit per‑session override, logged.
- Short/common usernames (`bob`, `jordan`): recall vs breaking code identifiers — needs a corpus to tune.
