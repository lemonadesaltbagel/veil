"""Fixture and seed files in the repo: what agents actually read.

Handles JSON (array of records, {"users": [...]} maps, Django fixtures
`[{"model": ..., "pk": ..., "fields": {...}}]`), JSON Lines and CSV. Each file
(or each top-level key) becomes a container; the same classifier and grouping
as databases apply, so `fixtures/users.json` and the dev DB share pseudonyms.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Iterable

from ..detect import KnownValues
from .core import Container, Report
from .sql import run

EXTS = {".json", ".jsonl", ".ndjson", ".csv"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".veil", "captures"}


def _ext(v):
    """Unwrap MongoDB extended JSON: {"$oid": x}, {"$date": x}, {"$numberLong": x} -> x."""
    if isinstance(v, dict):
        if len(v) == 1 and next(iter(v)).startswith("$"):
            return _ext(next(iter(v.values())))
        return {k: _ext(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_ext(x) for x in v]
    return v


def _records(path: str) -> dict[str, list[dict]]:
    name = os.path.splitext(os.path.basename(path))[0]
    ext = os.path.splitext(path)[1].lower()
    with open(path, encoding="utf-8", errors="replace") as f:
        if ext == ".csv":
            return {name: list(csv.DictReader(f))}
        text = f.read()
    if ext in (".jsonl", ".ndjson"):
        return {name: [_ext(json.loads(line)) for line in text.splitlines() if line.strip()]}
    try:
        data = _ext(json.loads(text))
    except json.JSONDecodeError as e:
        if "Extra data" not in str(e):  # JSON Lines saved as .json (mongoexport does this)
            raise
        return {name: [_ext(json.loads(line)) for line in text.splitlines() if line.strip()]}
    if isinstance(data, list) and data and all(isinstance(d, dict) for d in data):
        if all("model" in d and "fields" in d for d in data):  # Django fixture
            out: dict[str, list[dict]] = {}
            for d in data:
                out.setdefault(d["model"], []).append({"pk": d.get("pk"), **d["fields"]})
            return out
        return {name: data}
    if isinstance(data, dict):
        lists = {k: v for k, v in data.items() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)}
        return {f"{name}.{k}": v for k, v in lists.items()} if lists else {name: [data]}
    return {}


def iter_files(paths: Iterable[str]) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                yield from (os.path.join(root, f) for f in files if os.path.splitext(f)[1].lower() in EXTS)
        elif os.path.splitext(p)[1].lower() in EXTS:
            yield p


def seed_files(known: KnownValues, paths: Iterable[str], max_bytes: int = 50_000_000) -> Report:
    containers, data = [], {}
    for path in iter_files(paths):
        if os.path.getsize(path) > max_bytes:
            continue
        try:
            groups = _records(path)
        except (ValueError, UnicodeError, csv.Error):
            continue
        for name, recs in groups.items():
            key = next((k for k in ("id", "pk", "_id", "uuid") if recs and k in recs[0]), None)
            rows = [{"__key": (r.get(key) if key else i), **r} for i, r in enumerate(recs)]
            cols = {k: {"json": isinstance(v, (dict, list))} for r in rows[:300] for k, v in r.items() if k != "__key"}
            containers.append(Container(name, "__key", cols, rows[:300], {}))
            data[name] = rows
    return run(known, containers, lambda c, cols: iter(data[c.name]))
