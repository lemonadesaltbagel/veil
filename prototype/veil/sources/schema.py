"""Seeding hints from application code: which fields hold personal data, as declared by
the ORM schema or annotations, before (or without) looking at any data.

    Prisma         schema.prisma   `/// @pii email`, `/// @encrypted` (prisma-field-encryption), @map
    Django         models.py       EmailField, GenericIPAddressField, PhoneNumberField, `# pii: kind`
    Rails          db/schema.rb    tables; app/models/*.rb `encrypts :ssn, :email`, filter_attributes
    SQLAlchemy     *.py            __tablename__, EmailType / IPAddressType / PhoneNumberType / PasswordType
    OpenAPI        openapi.json    `format: email|ipv4`, `x-pii: kind`
    protobuf       *.proto         `[debug_redact = true]`, `// pii: kind`

The result maps a table/model key (lower-case, singular) to {field: kind}; `pii` means
"sensitive, kind unknown". It holds names only, never values, and is applied by
`core.plan()` with priority over name rules (but under explicit column comments).
"""

from __future__ import annotations

import json
import os
import re

KINDS = {"email", "username", "first_name", "last_name", "name", "phone", "ipv4", "address", "secret", "id_number"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", "vendor", ".tox"}
COMMENT_TAG = re.compile(r"(?:#|//)/?\s*@?pii\s*[:=]?\s*([a-z_]*)", re.I)

DJANGO_TYPES = {"EmailField": "email", "GenericIPAddressField": "ipv4", "IPAddressField": "ipv4",
                "PhoneNumberField": "phone"}
SA_TYPES = {"EmailType": "email", "IPAddressType": "ipv4", "PhoneNumberType": "phone", "PasswordType": "secret"}


def key(name: str) -> str:
    """Table/model/container name -> comparison key: last dotted part, lower-case, singular."""
    k = name.split(".")[-1].split(":")[-1].lower()
    for suffix, repl in (("ies", "y"), ("sses", "ss"), ("ses", "s"), ("s", "")):
        if k.endswith(suffix) and len(k) > len(suffix) + 2 and not k.endswith("ss"):
            return k[: -len(suffix)] + repl
    return k


def _tag(line: str) -> str | None:
    m = COMMENT_TAG.search(line)
    if not m:
        return None
    kind = m.group(1).lower()
    return kind if kind in KINDS else "pii"


def _add(hints: dict, table: str, field: str, kind: str) -> None:
    bucket = hints.setdefault(key(table), {})
    if bucket.get(field.lower()) in (None, "pii"):
        bucket[field.lower()] = kind


def _prisma(text: str, hints: dict) -> None:
    for m in re.finditer(r"model\s+(\w+)\s*\{(.*?)\n\}", text, re.S):
        model, body = m.group(1), m.group(2)
        table = re.search(r'@@map\("([^"]+)"\)', body)
        lines, pending = body.splitlines(), None
        for line in lines:
            s = line.strip()
            if s.startswith("///"):
                pending = "pii" if "@encrypted" in s else (_tag(s) or pending)
                continue
            fm = re.match(r"(\w+)\s+\w+", s)
            if not fm or s.startswith("@@"):
                pending = None
                continue
            kind = _tag(s) or ("pii" if "@encrypted" in s else None) or pending
            pending = None
            if kind:
                col = re.search(r'@map\("([^"]+)"\)', s)
                for t in {model, table.group(1) if table else model}:
                    _add(hints, t, fm.group(1), kind)
                    if col:
                        _add(hints, t, col.group(1), kind)


def _python(text: str, hints: dict) -> None:
    # Django models and SQLAlchemy declarative classes
    for m in re.finditer(r"^class\s+(\w+)\((.*?)\):\n((?:[ \t]+.*\n|\n)*)", text, re.M):
        name, bases, body = m.group(1), m.group(2), m.group(3)
        tables = {name}
        t = re.search(r"__tablename__\s*=\s*['\"](\w+)['\"]", body) or re.search(r"db_table\s*=\s*['\"](\w+)['\"]", body)
        if t:
            tables.add(t.group(1))
        for line in body.splitlines():
            fm = re.match(r"\s+(\w+)\s*(?::\s*[^=]+)?=\s*(.*)", line)
            if not fm:
                continue
            field, expr = fm.group(1), fm.group(2)
            kind = _tag(line)
            if not kind:
                for typ, k in {**DJANGO_TYPES, **SA_TYPES}.items():
                    if re.search(rf"\b{typ}\b", expr):
                        kind = k
                        break
            if kind:
                col = re.search(r"(?:Column|mapped_column)\(\s*['\"](\w+)['\"]", expr) or \
                    re.search(r"db_column\s*=\s*['\"](\w+)['\"]", expr)
                for tbl in tables:
                    _add(hints, tbl, col.group(1) if col else field, kind)


def _rails_schema(text: str, hints: dict) -> None:
    for m in re.finditer(r'create_table\s+"(\w+)".*?\n(.*?)\n\s*end', text, re.S):
        for line in m.group(2).splitlines():
            fm = re.match(r'\s*t\.\w+\s+"(\w+)"', line)
            kind = _tag(line)
            if fm and kind:
                _add(hints, m.group(1), fm.group(1), kind)


def _rails_model(text: str, hints: dict) -> None:
    cls = re.search(r"class\s+(\w+)\s*<", text)
    if not cls:
        return
    table = re.search(r"self\.table_name\s*=\s*['\"](\w+)['\"]", text)
    names = set()
    for m in re.finditer(r"^\s*encrypts\s+(.*)$", text, re.M):
        names |= set(re.findall(r":(\w+)", m.group(1).split("deterministic")[0]))
    for m in re.finditer(r"filter_attributes\s*\+?=\s*(.*)$", text, re.M):
        names |= set(re.findall(r":(\w+)", m.group(1)))
    for n in names:
        for t in {cls.group(1), table.group(1) if table else cls.group(1)}:
            _add(hints, t, n, "pii")


def _openapi(data, hints: dict) -> None:
    schemas = (data.get("components") or {}).get("schemas") or data.get("definitions") or {}
    for name, sch in schemas.items():
        for prop, spec in ((sch or {}).get("properties") or {}).items():
            if not isinstance(spec, dict):
                continue
            kind = spec.get("x-pii")
            kind = (kind if kind in KINDS else "pii") if kind else {"email": "email", "ipv4": "ipv4"}.get(spec.get("format"))
            if kind:
                _add(hints, name, prop, kind)


def _proto(text: str, hints: dict) -> None:
    for m in re.finditer(r"message\s+(\w+)\s*\{(.*?)\n\}", text, re.S):
        for line in m.group(2).splitlines():
            fm = re.match(r"\s*(?:repeated\s+|optional\s+)?\w[\w.]*\s+(\w+)\s*=\s*\d+", line)
            if not fm:
                continue
            kind = _tag(line) or ("pii" if re.search(r"debug_redact\s*=\s*true", line) else None)
            if kind:
                _add(hints, m.group(1), fm.group(1), kind)


def scan(project: str, max_files: int = 5000) -> dict[str, dict[str, str]]:
    """Walk a project and collect field hints from every schema/model file found."""
    hints: dict[str, dict[str, str]] = {}
    seen = 0
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in files:
            path = os.path.join(root, f)
            if seen >= max_files:
                return hints
            try:
                if f.endswith(".prisma"):
                    _prisma(open(path, encoding="utf-8").read(), hints)
                elif f.endswith(".py") and os.path.getsize(path) < 2_000_000:
                    text = open(path, encoding="utf-8", errors="ignore").read()
                    if "models.Model" in text or "__tablename__" in text or "pii" in text.lower():
                        _python(text, hints)
                elif f == "schema.rb":
                    _rails_schema(open(path, encoding="utf-8").read(), hints)
                elif f.endswith(".rb") and os.sep + "models" + os.sep in path:
                    _rails_model(open(path, encoding="utf-8").read(), hints)
                elif f.endswith(".proto"):
                    _proto(open(path, encoding="utf-8").read(), hints)
                elif re.fullmatch(r"(openapi|swagger)[\w.-]*\.json", f):
                    _openapi(json.load(open(path, encoding="utf-8")), hints)
                else:
                    continue
                seen += 1
            except (OSError, ValueError, UnicodeError):
                continue
    return {k: v for k, v in hints.items() if v}
