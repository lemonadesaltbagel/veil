"""MongoDB source: schema-less, so field paths are inferred from a sample.

Nested documents and arrays are flattened (`address.street`, `emails[]`,
`phones[].number`). References are inferred: a top-level `user_id` / `userId`
/ `customer` field whose values are ids of a person collection (`users`,
`customers`) groups the document with that person.
"""

from __future__ import annotations

import re
from typing import Any

from ..detect import KnownValues
from .core import Container, Report
from .sql import run

REF = re.compile(r"^(?P<base>[a-zA-Z]+?)(?:_id|Id|_ref)?$")


def _norm(v: Any) -> Any:
    from bson import ObjectId
    if isinstance(v, ObjectId):
        return str(v)
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return None
    return v


ID_LIKE = re.compile(r"^(?:[0-9a-f]{24}|\d+|[0-9a-f-]{36})$")


def seed_mongo(known: KnownValues, uri: str | None, database: str, max_docs: int = 500_000,
               client=None, delta: dict | None = None) -> Report:
    """delta: {collection: highest ObjectId _id seen}; ObjectIds grow with insert time."""
    if client is None:
        from pymongo import MongoClient
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client[database]
    names = [n for n in db.list_collection_names() if not n.startswith("system.")]
    samples = {n: [_norm(d) for d in db[n].aggregate([{"$sample": {"size": 300}}])] for n in names}
    containers = []
    for n in names:
        sample = samples[n]
        top: dict[str, dict] = {}
        for d in sample:
            for k, v in d.items():
                if k != "_id" and isinstance(v, (str, dict, list)):
                    top.setdefault(k, {"json": False, "comment": None})
        fks = {}
        for k in list(top):
            m = REF.match(k)
            if not m or k == m.group("base"):
                continue
            base = m.group("base").lower()
            target = next((t for t in names if t.lower() in (base, base + "s", base + "es")), None)
            vals = [str(d[k]) for d in sample if d.get(k) is not None][:50]
            # only a reference if it holds ids; mflix sessions.user_id holds an *email*
            if target and target != n and vals and all(ID_LIKE.match(v) for v in vals):
                fks[k] = (target, False)
                top.pop(k)
        if sample:
            containers.append(Container(n, "_id", top, sample, fks))

    def fetch(c: Container, cols: list[str]):
        proj = {k: 1 for k in set(cols) | set(c.fks)}
        query = {"_id": {"$gt": delta[c.name]}} if delta is not None and c.name in delta else {}
        for d in db[c.name].find(query, proj).sort("_id", 1).limit(max_docs):
            if delta is not None and type(d.get("_id")).__name__ == "ObjectId":
                delta[c.name] = d["_id"]
            yield _norm(d)
    return run(known, containers, fetch, delta)
