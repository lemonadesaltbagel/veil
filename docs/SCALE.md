# Veil — Scale: a million seeded values

*2026-10-21. Benchmark: `prototype/veil_dev/scale.py`. Apple M-series, 32 GB, Python 3.14.*

```bash
cd prototype && uv run python -m veil_dev.scale --people 150000   # ~1.2M seeded values
```

The benchmark creates a synthetic `customers` table: unique made-up names (not dictionary words), plus emails, usernames, phones and street addresses. It seeds the table the way `veil seed` does, then measures four things:

- the build of each index;
- memory;
- the full request pipeline (redaction + outbound guard) on a realistic **234 KB request**: a 30-turn conversation in which every third tool result is a 40-row query output containing real customers;
- a long session that touches 12k+ different people, then a re-seed after 100 new customers are inserted.

## Result: 150,000 people = 1,197,806 seeded values (+1.2M encoded aliases)

| | before (0.1.2 code) | after | |
|---|---:|---:|---|
| seeding (SQLite) | 3.7 s | 3.7 s | |
| redaction matcher build | 8.4 s | **1.1 s** | anchored automaton |
| outbound-guard index build | 51.0 s | **3.8 s** | shared dictionary, no prefix strings, base64 decoded |
| resident memory after build | 4.9 GB | **1.14 GB** | |
| peak memory (incl. a re-seed swap) | 7.8 GB | **1.86 GB** | |
| request: redaction, p50 / max | 43 / 65 ms | **37 / 38 ms** | |
| request: guard, p50 / max | 86 / 815 ms | **68 / 69 ms** | GC freeze removes the tail |
| token pattern after 12k tokens: rebuild per new token | 419 ms | **0.04 ms** | incremental |
| rehydrate 30 KB with 12k tokens | 278 ms | **0.5 ms** | |
| **first request after a re-seed** | **94 s** | **0.11 s** | indexes built in the re-seed thread |
| unrepaired leaks in the payloads | 0 | 0 | |

At 15,000 people (120k values) the guard index is 186 MB, builds in 0.3 s, and requests take 33 + 65 ms. The red-team bypass matrix (21 techniques) and every leak test pass unchanged.

## What changed

1. **Anchored Aho-Corasick** (`veil/match.py`). In pyahocorasick each trie node is a C structure of roughly 100 bytes, so a million full-length needles cost gigabytes. Now only each needle's first six characters go into the automaton. An anchor hit is confirmed by looking up text slices in a set. The slice lengths to try come from a per-anchor bitmask of needle lengths. The semantics are unchanged: leftmost-longest, non-overlapping, identifier boundaries. A randomized test checks equivalence against the old regex (`tests/test_match.py`).
2. **Truncation check without prefix strings.** The guard used to store every 6..n-character head and tail of every value: 18.7M strings at this scale. Now a head is a value anchor followed by a line end, and a tail is a line start followed by a reversed tail anchor. Each candidate is confirmed by `bisect` over the sorted values (`Prefixes`).
3. **One dictionary.** The guard's seeded index reuses the redactor's matcher, which holds the same values and the same encoded forms. The guard stays independent in *where* it looks (every string, structure-blind), which was the point of having it.
4. **Base64 is decoded, not precomputed.** Before, every value needed three needles (one per byte alignment), 3.4M needles in all. Now each base64-looking run in the outgoing text is decoded at every alignment, and the plain matcher runs once over all decodings. A run with a hit is replaced by `[veil:base64-redacted]`. Runs over 4 KB are whole blobs (images, files) and are decoded from their start only. Only hits of six or more characters count, so random bytes don't produce false hits.
5. **Token pattern.** The rehydration regex was one alternation of every token and was recompiled on every new token. It is now a regex-compatible matcher that grows in place. A new anchor gets a fresh, small anchor-only automaton, swapped in so that concurrent requests are not disturbed.
6. **Re-seeding off the request path.** The re-seed thread builds the matcher and guard index for the new value set before swapping it in (`veil.reseed.warm`). It then calls `gc.freeze()`, because full cyclic collections over millions of long-lived tuples were pausing requests by up to ~90 ms. The re-seed interval stretches to 10× the last re-seed's duration (about 6 s here), keeping a constantly written large database under ~10% of one core.

## Limits that remain

- Memory is about 1 KB per seeded value, including its encoded aliases and the guard's transformed forms. For tens of millions of values, a compiled matcher (Rust `aho-corasick` / `daachorse`) would be the next step. Seeding a sample is another option, though any person who isn't seeded is then caught only by patterns and NER.
- A re-seed reads the whole source again. For very large tables, an incremental read (`WHERE updated_at > last`) would be cheaper. Fingerprints already avoid re-reading sources that haven't changed.
- Python threads share the GIL, so requests are slower while a re-seed runs (seconds at this scale).
