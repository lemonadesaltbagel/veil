"""Scale benchmark: how veil behaves with a large seeded dictionary.

    uv run python -m veil_dev.scale --people 150000      # ~1M seeded values

Builds a synthetic customers table in SQLite (unique, pronounceable names that are
not dictionary words; emails, usernames, phones, street addresses), then measures:
seeding, matcher and guard index build times, resident memory, and per-request
latency of the full pipeline (redact + outbound guard) on a realistic request
(a long conversation with query output containing seeded people), plus the
token-pattern rebuild after many distinct tokens.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import random
import resource
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time

from veil.anthropic import redact_request
from veil.detect import KnownValues
from veil.engine import Veil
from veil.guard import Guard
from veil.reseed import Reseeder
from veil.sources import seed
from veil.vault import Vault

ONSETS = ["b", "br", "c", "ch", "d", "dr", "f", "g", "gr", "h", "j", "k", "kl", "l", "m", "n", "p", "pr",
          "r", "s", "sh", "st", "t", "tr", "v", "w", "z"]
VOWELS = ["a", "e", "i", "o", "u", "ai", "ea", "ou", "y"]
CODAS = ["", "n", "r", "l", "s", "th", "nd", "rk", "x", "m"]


def _word(rng: random.Random, syllables: int) -> str:
    return "".join(rng.choice(ONSETS) + rng.choice(VOWELS) + rng.choice(CODAS) for _ in range(syllables)).capitalize()


def make_db(path: str, people: int, seed_: int = 7) -> None:
    rng = random.Random(seed_)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, email TEXT UNIQUE, "
                "username TEXT UNIQUE, phone TEXT, address TEXT)")
    seen: set[str] = set()
    rows = []
    for i in range(1, people + 1):
        while True:
            first, last = _word(rng, rng.choice((2, 3))), _word(rng, rng.choice((2, 3)))
            user = f"{first.lower()}{last.lower()[:3]}{rng.randrange(100)}"
            if user not in seen:
                seen.add(user)
                break
        email = f"{first.lower()}.{last.lower()}{rng.randrange(1000)}@{rng.choice(('mailbox.org', 'corp.example.com', 'gmx.net', 'fastmail.com'))}"
        phone = f"+44 7{rng.randrange(100, 999)} {rng.randrange(100000, 999999)}"
        addr = f"{rng.randrange(1, 400)} {_word(rng, 2)} {rng.choice(('Road', 'Lane', 'Avenue', 'Close'))}"
        rows.append((i, first, last, email, user, phone, addr))
    con.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    con.commit()
    con.close()


def rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / 2**20 if sys.platform == "darwin" else r / 1024  # bytes on macOS, KiB on Linux


def timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, (time.perf_counter() - t) * 1000


def make_request(db: str, rng: random.Random, people_in_output: int, turns: int) -> dict:
    con = sqlite3.connect(db)
    n = con.execute("SELECT max(id) FROM customers").fetchone()[0]
    ids = rng.sample(range(1, n + 1), people_in_output)
    rows = con.execute(f"SELECT * FROM customers WHERE id IN ({','.join(map(str, ids))})").fetchall()
    con.close()
    table = "\n".join("|".join(map(str, r)) for r in rows)
    filler = ("The handler validates the payload, normalises the address fields and retries the "
              "webhook with exponential backoff when the upstream returns a 5xx. ") * 40
    messages = []
    for t in range(turns):
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"toolu_{t}", "content": table if t % 3 == 0 else filler}]})
        messages.append({"role": "assistant", "content": [
            {"type": "text", "text": "Looking at the next part of the module. " + filler[:2000]},
            {"type": "tool_use", "id": f"toolu_{t + 1}", "name": "Bash", "input": {"command": "sqlite3 app.db 'select 1'"}}]})
    messages.append({"role": "user", "content": f"Why does {rows[0][1]} {rows[0][2]} ({rows[0][3]}) get two emails?"})
    return {"model": "m", "max_tokens": 1024, "system": [{"type": "text", "text": "You are a coding agent. " * 300}],
            "tools": [{"name": "Bash", "description": "Run a command", "input_schema": {"type": "object"}}],
            "messages": messages}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="veil_dev.scale")
    ap.add_argument("--people", type=int, default=150_000)
    ap.add_argument("--db", help="reuse/create the synthetic database here")
    ap.add_argument("--requests", type=int, default=20)
    ap.add_argument("--json", help="write the measurements here")
    args = ap.parse_args(argv)

    db = args.db or os.path.join(tempfile.mkdtemp(prefix="veil-scale-"), "big.db")
    res: dict = {"people": args.people}
    if not os.path.exists(db):
        _, res["make_db_ms"] = timed(lambda: make_db(db, args.people))
    res["rss_start_mb"] = rss_mb()

    known = KnownValues()
    _, res["seed_ms"] = timed(lambda: seed(known, db))
    res["values"], res["aliases"] = len(known), len(known._aliases)
    res["rss_seeded_mb"] = rss_mb()

    _, res["known_matcher_build_ms"] = timed(lambda: known.find("warm up"))
    res["rss_known_matcher_mb"] = rss_mb()

    veil = Veil(Vault(":memory:", b"scale"), known)
    guard = Guard(veil)
    _, res["guard_build_ms"] = timed(lambda: guard.enforce({"messages": [{"role": "user", "content": "warm up"}]}))
    res["guard_norm_needles"] = sum(map(len, guard._seeded.norm.values()))
    res["guard_truncatable_values"] = len(guard._seeded.heads)
    res["rss_guard_mb"] = rss_mb()
    gc.freeze()  # as `veil proxy` does after building (veil.reseed.warm)

    rng = random.Random(11)
    lat_redact, lat_guard, sizes, leaks = [], [], [], 0
    for i in range(args.requests):
        body = make_request(db, rng, people_in_output=40, turns=30)
        sizes.append(len(json.dumps(body)))
        red, ms = timed(lambda: redact_request(veil, body))
        lat_redact.append(ms)
        (out, findings), ms = timed(lambda: guard.enforce(red))
        lat_guard.append(ms)
        leaks += sum(1 for f in findings if not f.repaired and not f.allowed)
    res["request_kb_median"] = statistics.median(sizes) / 1024
    res["redact_ms_p50"], res["redact_ms_max"] = statistics.median(lat_redact), max(lat_redact)
    res["guard_ms_p50"], res["guard_ms_max"] = statistics.median(lat_guard), max(lat_guard)
    res["unrepaired_findings"] = leaks
    res["tokens_after_requests"] = len(veil.vault.tokens())

    # Long session: many distinct people touched -> the rehydration pattern grows.
    con = sqlite3.connect(db)
    sample = [r[0] for r in con.execute("SELECT email FROM customers ORDER BY random() LIMIT 10000")]
    con.close()
    for e in sample:
        veil.redact(e)
    res["tokens_long_session"] = len(veil.vault.tokens())
    _, res["token_pattern_build_ms"] = timed(veil.token_pattern)
    text = " ".join(veil.redact(e) for e in sample[:200]) + " plain words " * 2000
    _, res["rehydrate_ms"] = timed(lambda: veil.rehydrate(text))
    veil.vault.token_for("email", "brand.new.person@elsewhere.org")  # one more token
    _, res["token_pattern_rebuild_after_1_new_ms"] = timed(veil.token_pattern)

    # Re-seeding: new customers appear; the background thread re-reads the source and
    # builds the indexes before the swap, so the next request must not pay for them.
    db2 = db + ".reseed.db"
    shutil.copy(db, db2)
    con = sqlite3.connect(db2)
    n = con.execute("SELECT max(id) FROM customers").fetchone()[0]
    con.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(n + i, f"Zorvath{i}", f"Quillen{i}", f"zorvath.quillen{i}@newcomer.example.net",
                      f"zquillen{i}", f"+44 7700 9{i:05d}", f"{i} Newcomer Road") for i in range(1, 101)])
    con.commit()
    con.close()
    rs = Reseeder(veil, [db2], log=open(os.devnull, "w"))
    added, res["reseed_ms"] = timed(rs.check_once)
    res["reseed_added_values"] = added
    body = make_request(db, rng, people_in_output=40, turns=30)
    body["messages"][-1]["content"] += " Also check zorvath.quillen7@newcomer.example.net."
    red, ms1 = timed(lambda: redact_request(veil, body))
    (out, _), ms2 = timed(lambda: guard.enforce(red))
    res["first_request_after_reseed_ms"] = ms1 + ms2
    res["new_customer_redacted"] = "zorvath.quillen7" not in json.dumps(out)
    os.remove(db2)
    res["rss_end_mb"] = rss_mb()

    gc.collect()
    w = max(map(len, res))
    for k, v in res.items():
        print(f"{k:<{w}}  {v:,.1f}" if isinstance(v, float) else f"{k:<{w}}  {v:,}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
