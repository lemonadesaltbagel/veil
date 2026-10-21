"""DynamoDB seeding (botocore; `pip install "veil-proxy[bedrock]"` brings it).

    dynamodb://us-east-1                         every table in the region
    dynamodb://us-east-1/Users,Orders            some tables
    dynamodb://local/AppTable?endpoint=http://127.0.0.1:8000   DynamoDB Local / LocalStack

Single-table designs put personal data inside keys: `PK = USER#alice@x.com`,
`GSI1SK = EMAIL#alice@x.com`. Every key attribute (table and GSI keys) is split on
`#` and each segment becomes a column named by its prefix (`PK:USER`), so a column holds
one kind of value and classifies cleanly. Items sharing a partition key are one record
group (one person in single-table designs); other items join a person through a matching
email or username, as with other sources.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..detect import KnownValues
from .core import Container, Report
from .sql import run


def _client(uri: str):
    import botocore.session
    u = urlparse(uri)
    q = parse_qs(u.query)
    region = (u.hostname or "us-east-1") if u.hostname != "local" else "us-east-1"
    return botocore.session.get_session().create_client(
        "dynamodb", region_name=region, endpoint_url=(q.get("endpoint") or [None])[0]), \
        [t for t in u.path.strip("/").split(",") if t]


def _value(v: dict) -> Any:
    (t, x), = v.items()
    if t == "S":
        return x
    if t == "N":
        d = Decimal(x)
        return int(d) if d == d.to_integral_value() else float(d)
    if t == "BOOL":
        return x
    if t == "NULL":
        return None
    if t == "M":
        return {k: _value(y) for k, y in x.items()}
    if t == "L":
        return [_value(y) for y in x]
    if t in ("SS", "NS"):
        return [_value({t[0]: y}) for y in x]
    return None  # B, BS: binary, never seeded


def item(raw: dict, key_attrs: list[str]) -> dict:
    """Deserialised item, plus one column per key segment: PK=USER#a@x.com -> PK:USER = a@x.com."""
    rec = {k: _value(v) for k, v in raw.items()}
    for attr in key_attrs:
        v = rec.get(attr)
        if isinstance(v, str) and "#" in v:
            prefix, *segs = v.split("#")
            for i, seg in enumerate(segs):
                rec[f"{attr}:{prefix}" + (f"#{i + 1}" if i else "")] = seg
    return rec


def _key_attrs(desc: dict) -> tuple[str, list[str]]:
    t = desc["Table"]
    hash_key = next(k["AttributeName"] for k in t["KeySchema"] if k["KeyType"] == "HASH")
    attrs = [k["AttributeName"] for k in t["KeySchema"]]
    for idx in t.get("GlobalSecondaryIndexes", []) + t.get("LocalSecondaryIndexes", []):
        attrs += [k["AttributeName"] for k in idx["KeySchema"]]
    return hash_key, list(dict.fromkeys(attrs))


def seed_dynamodb(known: KnownValues, uri: str, client=None, max_items: int = 500_000) -> Report:
    ddb, tables = (client, urlparse(uri).path.strip("/").split(",")) if client else _client(uri)
    tables = [t for t in tables if t]
    if not tables:
        for page in ddb.get_paginator("list_tables").paginate():
            tables += page["TableNames"]

    def scan(table: str, keys: list[str], limit: int):
        n, start = 0, None
        while n < limit:
            kw = {"TableName": table, "Limit": min(1000, limit - n)}
            if start:
                kw["ExclusiveStartKey"] = start
            page = ddb.scan(**kw)
            for raw in page.get("Items", []):
                yield item(raw, keys)
                n += 1
            start = page.get("LastEvaluatedKey")
            if not start:
                return

    containers, keys = [], {}
    for table in tables:
        hash_key, attrs = _key_attrs(ddb.describe_table(TableName=table))
        keys[table] = attrs
        sample = list(scan(table, attrs, 300))
        cols = {c: {"json": isinstance(v, (dict, list))} for r in sample for c, v in r.items() if c != hash_key}
        containers.append(Container(table, hash_key, cols, sample, {}))
    return run(known, containers, lambda c, _cols: scan(c.name, keys[c.name], max_items))
