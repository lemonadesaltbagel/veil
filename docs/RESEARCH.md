# Veil — Research: PII redaction for AI coding agents

*Date: 2026-10-18. Status: research + working prototype (`prototype/`).*

## 1. Problem

When a developer works with an AI coding agent (Claude Code, Codex CLI, Cursor, …), every byte the
agent reads is sent to the model provider: DB query output, fixture files, logs, CSVs, stack traces,
`git log` author emails, even the working-directory path in the system prompt (`/Users/<name>/…`).
Some developers and companies require that **real user identities never leave the machine** — the
model should reason about `user_cq5f` / `user_cq5f@example.test`, while commands still run against the
real data locally.

That is **reversible, consistent pseudonymization at the LLM context boundary**, with three hard
sub‑problems:

1. **Detection** in developer artifacts (code, logs, SQL results, JSON) — not prose.
2. **Round‑tripping** through the agent loop: model output (commands, edits) contains tokens that
   must sometimes become real again locally, and sometimes must not.
3. **Protocol fidelity**: streaming, prompt caching, signed thinking blocks, tool‑use JSON.

## 2. Where can you intercept? (verified against Claude Code docs)

| Point | Sees everything? | Can rewrite? | Fails | Notes |
|---|---|---|---|---|
| **`ANTHROPIC_BASE_URL` proxy** | **Yes** — system prompt, user prompt, tool results, history | Yes, both directions | Closed (you control it) | Official "LLM gateway" support. Works with claude.ai subscription logins if `anthropic-beta` is forwarded verbatim (it carries the OAuth capability). Managed setting `allowedProviders: ["customEndpoint"]` can *force* every session through the proxy (v2.1.285+). |
| PostToolUse hook `updatedToolOutput` | Tool results only | Yes, all tools | **Open** — a value not matching the tool's output schema is silently ignored and the *original* is sent | Docs: "Telemetry such as OpenTelemetry tool spans … captures the original output before the hook runs." Community reports of it being ignored for Bash/WebFetch in some versions (unverified whether fixed). |
| PreToolUse hook `updatedInput` | Tool inputs | Yes, all tools | Open | Good place to rehydrate tokens → real for local execution. |
| UserPromptSubmit hook | Prompt | **No** (block or add context only) | — | Cannot redact what the user types. |
| Permission deny rules / sandbox `denyRead` | — | Block only | — | `Read(...)` deny doesn't cover Bash subprocesses; sandbox is the OS‑level enforcement. Use to keep raw dumps/.env out entirely. |
| Masking DB MCP server / masked DB role | DB results only | n/a | Closed | Strongest for DB reads (pg_anonymizer `MASKED` role). Doesn't cover logs/files. |

Gateway constraints that a proxy must respect (from *gateway compatibility guide*):
forward `anthropic-*` headers & unknown body fields verbatim; keep SSE `ping`s flowing (idle
watchdog); forward error bodies unmodified (Claude Code's retry logic matches on wording);
don't break signed thinking blocks (Claude Code would strip thinking on signature errors).
Claude Code also prepends an attribution block to the system prompt — leave it unchanged.

**Conclusion:** the proxy is the only layer that both sees everything and fails closed. Hooks are
useful defence‑in‑depth and for agents/setups where a proxy is impossible; DB masking is the best
*source* control. Other agents: Codex CLI/Aider support custom base URLs (proxy works); Cursor and
Copilot route through vendor backends (proxy mostly not possible — unverified), so they'd need
hooks/MCP.

## 3. Existing landscape

### Detection engines
- **Microsoft Presidio** (MIT, ~11k★, moving to a "data-privacy-stack" org). Recognizer registry,
  regex + checksum + context words + spaCy/transformers NER; operators replace/mask/hash/encrypt.
  *Code findings:* deanonymization is **position‑based** (needs offsets from the anonymize call) so
  it can't restore tokens inside LLM‑generated text; `hash` uses a random salt per entity and
  `encrypt` a random IV → **no consistent pseudonyms built in**; the docs' sample
  `InstanceCounterAnonymizer` skips index 1. Default model `en_core_web_lg` (~560 MB).
  REDACT benchmark reports ~0.07 recall on high‑risk entities.
- **OpenAI Privacy Filter** (Apache‑2.0, Apr 2026): 1.5B MoE / ~50M active, CPU‑friendly, 8 labels
  incl. `secret`. Becoming the default local NER backend. **NVIDIA GLiNER‑PII** — zero‑shot custom
  labels (useful for "username", "tenant_id"). **StarPII** — the only code‑specific PII model (gated, 2023).
- **LLM Guard** (MIT, **archived Jul 2026**). Anonymize + `Vault` + Deanonymize. *Code findings:*
  vault is an in‑memory list (no persistence, no tenant isolation); `CASE_INSENSITIVE` deanonymize
  passes the placeholder **unescaped to `re.sub`** — `[REDACTED_PERSON_1]` becomes a character class
  (verified, `output_scanners/deanonymize.py:60`); fuzzy mode lets `…_1` overwrite `…_2`.

### Gateways
- **LiteLLM** Presidio guardrail (`output_parse_pii`). *Code findings (v1.107):* tokens are
  `<PERSON_n>` numbered **by position within each message part** (verified, `presidio.py:886`), so the
  same person gets different numbers in different messages and assignment depends on async
  completion order → breaks coreference **and prompt caching**; Anthropic SSE unmasking is per
  chunk, so a token split across deltas is never restored; restored values are inserted into JSON
  tool arguments without escaping; mapping lives for one request only.
- Portkey (irreversible redaction), Kong AI Sanitizer (enterprise, reversible), Cloudflare AI Gateway
  DLP (flag/block only), Skyflow / Private AI / Protecto (commercial reversible vaults),
  Prompt Security / Nightfall (enterprise DLP, mostly blocking).

### Coding‑agent‑specific (all small/new; existence confirmed via HTTP)
- `paroque28/claude-code-redact` (Apache‑2.0): base‑URL proxy + hooks, SHA‑256 deterministic tokens.
- `karanb192/claude-code-redact` (MIT): hooks; checksum‑validated regex set; restores only in Edit/Write.
- `crp4222/PrivAiTe` (BSD‑3): proxy for Claude Code/Codex, Presidio + Privacy Filter, per‑request mapping.
- `zeroc00I/DontFeedTheAI` (MIT, ~670★): proxy + local Ollama detector, pentest focus.
- `CupOfGeo/llm-redact-proxy` (MIT): fail‑closed, keyed‑hash cache‑stable placeholders.
- `CSPF-Founder/redactproxy` (GPL‑3): honest known‑gaps list (cwd in system prompt, thinking blocks, base64).
- DB MCPs: `pg-redact-mcp`, `mcp-pii-shield` — column‑name heuristics, Postgres only.

### Data‑source masking
**PostgreSQL Anonymizer 2.0** (dynamic masking per role, deterministic `pseudonymize`) — best
control for agent DB access. **Greenmask** (Apache‑2.0, deterministic hash transformers for
dumps). Neosync archived (2025‑08); Replibyte unmaintained.

### Research findings that shape the design
- NER recall degrades badly out of distribution (noisy/informal/code); regex is most robust for
  structured IDs (arXiv 2609.03464). No public benchmark exists for PII in logs/CSVs/SQL output.
- **Consistent pseudonyms beat masks** for task utility; retrieval collapses with masks (2609.11335).
  Type‑consistent surrogates beat placeholders (SurrogateShield, 2606.29567).
- Removing explicit identifiers does not stop attribute inference/re‑identification from context
  (Staab et al.; 2605.30848) → quasi‑identifiers (rare values, tenant names) are a residual risk.

## 4. Gaps Veil can fill

1. **Known‑value detection seeded from the developer's own data.** Every existing tool *guesses*
   with regex/NER. But the developer *has* the ground truth: the `users` table. Seeding an exact‑match
   dictionary from PII columns gives near‑perfect recall for the values that actually matter, in
   any format (logs, free‑text notes, JSON, code), with no ML. Demo: the order note
   `"gift for Raj Kapoor"` is caught without NER.
2. **Row‑coherent pseudonyms.** All PII of one record shares a code (`user_cq5f`,
   `user_cq5f@example.test`, `User Cq5f`), so the model can still reason "this email belongs to that
   user". Nobody else does this.
3. **Sink‑aware rehydration policy.** Decide per tool whether tokens become real: full for
   Bash/Read/Grep (so queries hit real data), *preserve‑only* for Edit/Write (rehydrate only values
   already in the target file — the agent can never introduce real PII into source code), none for
   WebFetch, unknown tools, or network‑capable commands (prompt‑injection exfiltration guard).
4. **Protocol correctness**: deterministic HMAC tokens → byte‑stable history → prompt cache hits;
   streaming holdback for split tokens; thinking blocks untouched; JSON‑aware restore (escaping correct).
5. **Assurance**: a leak‑test harness against the real upstream payload, a "what the model saw"
   view, fail‑closed defaults.

## 5. Recommended to borrow

- Presidio's recognizer abstraction (regex + checksum validators + context words) as an optional
  layer; Privacy Filter / GLiNER‑PII as pluggable NER for free text (lazy‑loaded, never required).
- karanb192's checksum‑validated, low‑false‑positive regex set; llm-redact-proxy's fail‑closed stance;
  redactproxy's known‑gaps checklist.
- pg_anonymizer / Greenmask for the "masked dev DB" source layer, and their deterministic transformer idea.

## 6. Mock-test findings (2026-10-19, Claude Code 2.1.285)

Real Claude Code CLI → veil → fake LLM, over Chinook data (see `prototype/captures/`):

- **Claude Code sends PII outside `system`/`messages`.** A top-level `safeguards[].classifier_context`
  carries `home_dir`, `user_identity`, cwd, git state. The first capture leaked the OS username
  there 16×. Fix: request redaction is now **default-deny** — every top-level field except a short
  list of pure config fields is redacted. Lesson: never allowlist where PII *might* be.
- `metadata.user_id` carries a device-id hash and session id (pseudonymous, left as is).
- Path round-trip works: the model sees `/Users/user_692m/…`, issues `Read` on that path, veil
  rehydrates it, the real file is read, its content is redacted on the way back.
- Only false positive in Claude Code's ~5.9k-char system prompt + 20 tool definitions:
  `noreply@anthropic.com` (now allowlisted with other no-reply senders). No first-name collisions.
- Stripe `sk_live_` keys initially leaked (pattern gap) → secret patterns extended.
- Values repeated across tables (Customer.Address = Invoice.BillingAddress) broke row coherence →
  first-seen group wins.

Free-text PII (ai4privacy, 1,000 rows, 3,096 labelled values):

| | name/contact labels* leaked | all labels leaked |
|---|---|---|
| patterns only (PII not in your data) | 83% | 94% |
| seeded from your data | **1.8%** | 71% |

\*first/middle/last name, email, username, phone, street, IPv4. Seeded misses are 3-letter names
(below min length) and glued tokens (`LaneKohler`). Emails: 100% caught either way; Luhn-valid cards:
100% (most dataset cards are not Luhn-valid). Not covered at all: passwords, URLs, dates, account
numbers, job titles, companies → confirms the design: seeding is the backbone for *your* users;
an NER layer is required for third-party free text.

## 7. Real-model results (2026-10-19, DeepSeek `deepseek-flash` via its Anthropic-format API)

Same Chinook scenario, real model choosing its own tools (read-only, sandboxed to a scratch dir):

| driver | requests | real values leaked | guard repairs | mangled tokens | cache hits | cost | outcome |
|---|---|---|---|---|---|---|---|
| Anthropic SDK loop | 10 | **0** | 0 | 0 | 88% | ~$0.005 | correct root cause (double charge, invoice 293) |
| Claude Code 2.1.285 CLI | 6 | **0** | 0 | 0 | 82% | ~$0.012 | correct root cause + sensible caveats |

- **Prompt caching survives pseudonymization** (deterministic tokens → stable prefixes).
- **Path round-trip works with a real model**: it issued `cd /Users/user_r7y8/... && ls`, veil
  rehydrated it, the command ran on the real path.
- **The model never wrote a malformed token** (case, truncation) in ~16 tool calls and long answers.
- **Fragment searches are the main utility gap.** Models grep/LIKE on *parts* of identifiers
  (`LIKE '%mz5z%'`, `grep "ps5n"`), which can't map to real data. A static system note
  (`PSEUDONYM_NOTICE`, cache-safe) reduced but did not eliminate this with a cheap model.
- The model inferred that `stripe key=secret_x` lines were plaintext credentials from context alone.
- veil overhead after switching to Aho–Corasick: ≤60 ms on 72k-char Claude Code requests (was ~400 ms).

## 8. Step 3 findings (2026-10-19): databases, NER, and a real bypass

**A real model bypassed redaction with a shell transform.** With veil + NER + Claude Code + DeepSeek,
the model noticed Read output was pseudonymised and ran `sed -n l app.log`. `l` prints non-ASCII as
octal (`Stra\303\237e`) and wraps lines with `\`, so `leonekoh\⏎ler@surfeu.de` matched nothing and
went upstream; the model decoded it in its reasoning. The audit's leak scan (plain matching) reported
0 leaks — it was caught only because the guard found real values in the returned thinking.
Fixes: byte-dump commands (`sed … l`, `od`, `xxd`, `hexdump`, `strings`, `cat -v/-A`, `base64`) are
replaced by a notice before they run; the guard decodes continuations/octal/`\x`/`\u` escapes and
withholds a string whose decoded form contains a real value; the audit leak scan decodes too. A rescan
of all stored captures found no other leak; the rerun was clean (0 leaks, 82% cache hits, $0.011).
**Lesson:** an agent with a shell can always transform data before veil sees it. Redaction at the
context boundary must be paired with command policy and decoding, and audits must check decoded forms.

**NER (GLiNER-PII edge, 46 MB ONNX, optional)** cuts free-text name/contact leaks 80% → 17.6%, but on
real agent traffic it tagged `claude-opus-5-5` (username), `14999989` (password) and "Claude Code"
(person). Combined with the structure-blind guard this rewrote the request's `model` field and Claude
Code's own system prompt (183 "repairs", cache hits 82% → 69%). Fixes: NER keeps only person/email/
phone/address labels, skips `<system-reminder>` blocks and a product-name allowlist; its guesses are
redacted where found but never become guard needles; the guard never touches scalar settings.

**Name tokens must compose.** With `User Ab12` for full names and `First_Ab12`/`Last_Ab12` for parts, the
model saw `First_X | Last_X` in the DB and `User X` in the log and reported a (non-existent) data-quality
issue. Full names are now `First_Ab12 Last_Ab12`.

**Fragments handled:** a bare person code outside a whole token (`LIKE '%mz5z%'`, `grep ps5n`) is expanded
to that person's real values for the Grep tool and replaced by a notice citing the real tokens for Bash.
With DeepSeek the notice fired 1–2× per session and the model switched to whole tokens each time.

Database seeding details: see `docs/DATABASES.md`.

## 9. Step 4 findings (2026-10-19): hardening

- **Rehydration is a data → code boundary.** Plain substitution let seeded values inject shell commands
  and break SQL (23/35 injection tests failed); quote-aware escaping fixes all 35.
- **An audit oracle that can't decode an attack reports false safety.** The first bypass matrix said
  15/20 contained; with an oracle that undoes the transforms the truth was 9/20. Now 20/20, with the
  oracle in CI.
- **Large real seeds contain dictionary words as names.** Redis sample people named *Code* and *Read*
  turned "Claude Code" into a pseudonym in the system prompt and would have renamed the `Read` tool.
- **Scale:** Python regex alternation of 12k emails cost 640 ms/request; Aho–Corasick: 8 ms.
- Final real-model regression (Claude Code + DeepSeek, all hardening on): 0 leaks under the decoding
  oracle, 0 repairs, correct diagnosis; context-aware escaping invisible in normal commands.

## 10. Step 5 findings (2026-10-19): adoption and other agents

- **Codex CLI 0.160 dropped Chat Completions** (`wire_api = "chat"` is no longer supported) — a veil for
  Codex must speak the Responses API. Probing the real CLI showed its shapes: `exec_command` with a `cmd`
  string, `write_stdin`, encrypted `reasoning` items, the cwd (username) inside `<environment_context>`.
  Real Codex → veil → fake Responses model: 0 leaks, commands ran with real values, answer rehydrated.
- **OpenAI SDK agent loop → veil → DeepSeek Chat Completions:** 11 requests, 0 leaks (decoding oracle),
  89% prompt-cache hits, correct diagnosis.
- **Project wiring works with nothing in the shell environment:** `veil init` + LaunchAgent + real Claude
  Code → DeepSeek, routed purely by the project's `settings.local.json`. It surfaced three real bugs no
  offline test had: a JSON-Schema property *named* `type` (dict value) crashed the guard's
  `type in set` check (only Claude Code's tool set for non-Claude model ids has one); hook processes and
  the proxy had divergent vault caches (a `card_…` token reached the developer); `launchctl bootstrap`
  raced the asynchronous `bootout`. All fixed with regression tests.

## 11. Open items, researched and built (2026-10-20)

- **Gateway auth for cloud providers**: Claude Code's docs prescribe `CLAUDE_CODE_SKIP_BEDROCK_AUTH` /
  `CLAUDE_CODE_SKIP_VERTEX_AUTH` with credentials injected by the gateway — the only workable design for
  a body-rewriting proxy (SigV4 covers the body). Bedrock's stream must stay binary eventstream with the
  original content-type. Real Claude Code in Bedrock and Vertex mode → veil → fake upstreams: 0 leaks.
  Not yet run against real AWS/GCP (no accounts).
- **Enforcement**: `allowedProviders: ["customEndpoint"]` + a managed `env` pin admits only the exact
  pinned gateway URL; drop-ins in `managed-settings.d/` let veil ship its policy without editing a shared
  file. Installing requires admin rights; not exercised end-to-end here (no sudo).
- **A test of mine wrote to the login keychain.** A "no keychain" test pointed `VEIL_KEYCHAIN` at a missing
  file; `security -i` ignored the path and stored a dummy secret in the login keychain while veil fell back
  to a file, hiding it. Fixed (a missing configured keychain is never used; no `security` call at all) with
  a regression test; the stray item (dummy test value) was deleted.
- Hooks via the proxy are 7× faster (39 ms vs 278 ms). Linux path verified in a container.

## 12. Display, re-seeding, pilot, CI, scale (2026-10-21)

- **Display is a mode, not a yes/no.** Real values by default, `veil display tokens` at runtime, and
  enforceable per team through a managed header that can only tighten. See DESIGN "Display modes".
- **Re-seeding.** A Postgres customer inserted while the proxy ran was pseudonymised on the next
  request after the fingerprint changed (end-to-end through the real proxy). Live fingerprint tests
  run for Postgres, MariaDB, Redis and MongoDB.
- **Pilot on a real repository** (`veil_dev.pilot`). Setup: veil's own repo, 39,650 seeded values,
  Claude Code with DeepSeek through veil. The task was to add a `--version` flag and run a test
  file. Results:
  - The task succeeded in 7 turns, with 72% cache reads and about $0.02 cost.
  - 0 seeded values leaked, and 0 pseudonyms were written into the code.
  - The only replacements were the developer's OS username (in paths) and git author name, so
    there were no false positives.

  Before that run, the pilot found a guard false positive. The transformed-value check stripped all
  whitespace, so two ordinary adjacent words could glue into a seeded surname (`At` + `cheson`).
  Fixed by checking two views:
  - a word view, which keeps spaces;
  - a character view, which squashes only s p a c e d - o u t runs.
- **CI on Linux found two portability bugs.** One was macOS-only `plutil` in a test. The other was
  GNU `cut -b`, which cuts UTF-8 mid-character. Decoding leaves U+FFFD there, which the truncation
  check now treats as a cut boundary (new bypass technique, 21/21 contained).
  A flaky red-team result was a harness false positive: a phone pseudonym is `555-01xx`, and a
  fictional real phone in Chinook can share those digits. The partial-leak scan now ignores text
  inside tokens; 0 failures in 150 runs.
- **Scale** (`docs/SCALE.md`), at 1.2M seeded values:
  - guard index build: 51 s → 3.8 s;
  - memory: 4.9 GB → 1.1 GB;
  - first request after a re-seed: 94 s → 0.11 s;
  - guard p50 / max: 86 / 815 ms → 68 / 69 ms.

- **Values in second languages** (python -c, heredocs, bash -c, jq, ...). Probing showed that a value
  restored inside `python3 -c "…'X'…"` was escaped only for the shell. That gave wrong values and
  syntax errors; nothing ran in the probe, but by luck. The rewrite models every layer. A fuzzer of
  random nestings, with every command executed, found 11 executions in its first 3,000 commands, all
  through output re-entering code: `eval eval X`, `$(printf %s X) | bash`, an unquoted heredoc with
  backticks. Rules for where output becomes code closed them: 0 in 50,000 since.
- **Two bugs found along the way:**
  - Fragment detection scanned `json.dumps(tool_input)`, where `\n` glued an `n` onto a token at
    the start of a line. Multi-line commands got a false "fragment" notice, and Edit content at a
    line start was not restored, so a pseudonym could be written into a file.
  - Per-project hooks did not carry their vault home. A hook rejected by the project's proxy fell
    back to the *default* vault.

- **Platforms.** According to Claude Code's docs, Microsoft Foundry and Claude Platform on AWS
  both speak plain Anthropic Messages + SSE at `{base}/v1/messages`.
  - Foundry authenticates with an API key or an Entra bearer token; neither covers the body, so
    both pass through veil unchanged.
  - Claude Platform on AWS adds the `anthropic-workspace-id` header and either a workspace key or
    SigV4. The skip-auth flag (`CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH`) lets a gateway sign. The SigV4
    service name is not documented.
  - Real Claude Code 2.1.285 in both modes, through veil to a scripted model: 0 leaks.
- **New data shapes** (SQL Server catalogs, Elasticsearch ecommerce events, Northwind-style
  columns) surfaced five classification bugs, listed in `docs/DATABASES.md`. The worst: `ShipAddress`
  was excluded as an IP-address column, so shipping addresses were never seeded.
- **Linux CI found that the dictionary-word filter depended on `/usr/share/dict/words`**, which
  Linux runners and Windows lack. There, first names like `Code` were seeded and rewrote "Claude
  Code". veil now ships the list.

## 13. Closing the remaining gaps (2026-10-21, after 0.2.1)

- **Database tool with bound parameters** (`veil mcp-db`). Real Claude Code through veil queried a
  customer by pseudonym. The real email was bound as a parameter, 3 invoices were found, the model
  saw only pseudonyms (2 requests, 0 leaks), and the developer saw real values. Building it found
  two gaps:
  - `PRAGMA writable_schema = 1` passed a first-keyword check. PRAGMA is now restricted to its
    schema-reading forms.
  - A literal holding only *part* of a pseudonym (`'%ab12%'`) passed untouched. It is now refused.
- **Values written into files** are escaped for the file's language at their landing spot. Each
  test result is parsed or executed.
- **Rare combinations of common values** (city + job title of one person) are detected by set
  intersection on demand.
- **New sources:** git history, DynamoDB (key segments), Snowflake and BigQuery (native tags).
  **Live servers in CI:** SQL Server with sensitivity classification and masking, Elasticsearch,
  DynamoDB Local.
- **Bugs found on the way:**
  - `Veil(vault, known)` replaced a value set holding only quasi-identifiers with an empty one,
    because `known or KnownValues()` treated it as falsy.
  - On Windows, git output decoded with cp1252 garbled non-ASCII author names.
  - Snowflake tag names arrive fully qualified (`SNOWFLAKE.CORE.SEMANTIC_CATEGORY`).
  - `detect()`'s overlap check was quadratic.
- **Team secrets** move through 1Password, AWS/GCP secret managers or Vault, and `team sync`
  follows a rotation.

## 14. Fragments of phone pseudonyms (2026-10-23)

A real session against the DeepSeek API (9 requests, 0 leaks, correct diagnosis) exposed a bug:

1. The model searched for a *fragment* of a phone pseudonym (`LIKE '%408-555-0133%'`).
2. On the next request, veil's phone pattern minted a *second* pseudonym for those digits.
3. The developer was then shown the first pseudonym instead of the real number.

A phone-pattern hit whose digits are those of one of veil's own phone pseudonyms is now skipped,
in redaction and in the guard. A blanket "skip the fictional 555-01xx range" fix was tried first: it
leaked a sample number from that range, and the red-team test caught it.

## 15. Known limitations (honest list)

- `write_stdin` (Codex interactive sessions) never receives real values, so interactive tools (e.g. a
  `sqlite3` REPL) see pseudonyms; non-interactive commands are unaffected.
- Local machine is trusted: real values live in the vault and Claude Code's local transcripts
  (rehydrated text), and OTel/analytics see original tool output (disable non‑essential traffic).
- Encoded forms: URL, JSON `\u`, NFD, base64 (guard decodes runs at every alignment), sed-`l`/octal/`\x`,
  case, spacing, reversal, rot13, hex, char codes and truncation (guard withholds or marks partial) are
  handled; arbitrary agent-written transforms (custom scripts) cannot all be anticipated.
- Short/common values (`bob`, `admin`, first names like `May`) need min‑length + stoplists → recall trade‑off.
- Images (screenshots) are passed through unscanned.
- Fragments of pseudonyms (LIKE/grep on part of a token) can't match real data. A Bash command
  containing one is replaced with a notice naming the whole tokens; a Grep pattern is expanded to that
  person's real values. A fragment assembled inside a script is not caught.
- Shell escaping models sh quoting, heredocs, substitutions and the common embedded interpreters,
  and values written into files are escaped for the file's language. A language veil doesn't know
  (a custom DSL in a string), or a file type without rules, gets the value as is. Prefer
  `veil mcp-db` for database access: it has no escaping to get wrong.
- Transform coverage is a matrix of 21 known techniques, not a proof: an agent can always invent a new
  encoding (custom scripts). Seeded values < 8 chars are only checked verbatim/encoded.
- Free‑text PII not in the seed (e.g. a support ticket mentioning a third party) needs the NER layer.
- Quasi‑identifiers: rare cities, postal codes, birth dates, companies and job titles of seeded people,
  and rare combinations of them on one line, are reported (or pseudonymised with `veil quasi redact`).
  Combinations spread over several lines are not. Neither are exact amounts and timestamps: they
  identify a person only together with the database, which never leaves the machine.
