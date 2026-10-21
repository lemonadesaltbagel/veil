"""Redis: no schema, so containers are *key patterns* inferred by replacing
ids in key names (`user:42` -> `user:{id}`, `sess:9f1c...` -> `sess:{id}`).

Values by type: hash -> fields; string -> JSON document, or a single field
named after the key's last segment (`user:42:email`); set/list/zset -> members.
Records group by their key; JSON sessions and sets join the right person
through value linking (a known email inside them).
"""

from __future__ import annotations

import json
import re

from ..detect import KnownValues
from .core import Container, Report
from .sql import run

ID_SEG = re.compile(r"^(?:\d+|[0-9a-fA-F]{16,}|[0-9a-fA-F-]{36}|[A-Za-z0-9_-]{20,})$")


def key_pattern(key: str) -> str:
    sep = ":" if ":" in key else ("/" if "/" in key else ":")
    return sep.join("{id}" if ID_SEG.match(seg) else seg for seg in key.split(sep))


def seed_redis(known: KnownValues, url: str, max_keys: int = 200_000, client=None) -> Report:
    if client is None:
        import redis
        client = redis.Redis.from_url(url, decode_responses=True, socket_timeout=10)
    keys = []
    for k in client.scan_iter(count=1000):
        keys.append(k)
        if len(keys) >= max_keys:
            break
    pipe = client.pipeline()
    for k in keys:
        pipe.type(k)
    types = pipe.execute()
    by_pattern: dict[str, list[tuple[str, str]]] = {}
    for k, t in zip(keys, types):
        by_pattern.setdefault(key_pattern(k), []).append((k, t))

    def read(items):
        pipe = client.pipeline()
        for k, t in items:
            {"hash": pipe.hgetall, "string": pipe.get, "set": pipe.smembers, "list": lambda k: pipe.lrange(k, 0, 999),
             "zset": lambda k: pipe.zrange(k, 0, 999)}.get(t, pipe.type)(k)
        for (k, t), v in zip(items, pipe.execute()):
            leaf = k.split(":")[-1] if ":" in k else "value"
            if t == "hash":
                rec = dict(v)
            elif t == "string":
                try:
                    doc = json.loads(v)
                    rec = doc if isinstance(doc, dict) else {leaf: doc}
                except (TypeError, ValueError):
                    rec = {leaf if not ID_SEG.match(leaf) else "value": v}
            elif t in ("set", "list", "zset"):
                rec = {f"{k.split(':')[-1]}": sorted(v) if t == "set" else list(v)}
            else:
                continue
            yield {"__key": k, **rec}

    containers, data = [], {}
    for pattern, items in by_pattern.items():
        sample = list(read(items[:300]))
        cols = {c: {"json": isinstance(val, (dict, list))} for r in sample for c, val in r.items() if c != "__key"}
        if cols:
            containers.append(Container(f"redis:{pattern}", "__key", cols, sample, {}))
            data[f"redis:{pattern}"] = items
    return run(known, containers, lambda c, cols: read(data[c.name]))
