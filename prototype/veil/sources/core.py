"""Source-independent seeding core.

Every data store is reduced to *containers* (table, collection, index) holding
*records* (rows, documents). A field is addressed by a path: `email`,
`profile.name.given`, `profile.emails[]`, `profile.phones[].number`.

Classification signals, strongest first:
  1. native tags   - a column comment / label such as `pii:email`
  2. names         - the field path (`work_email`, `name.family`, `phones[].number`)
  3. value sample  - >=80% of sampled values look like emails / phones / public IPs
                     (catches `contact`, `value`, `c1` columns)

Grouping: one person, one pseudonym code. A record's group is its own key,
unless it extends a person record through a foreign key that is unique (1:1,
e.g. accounts.customer_id) or it has no identity of its own (child data, e.g.
invoice.customer_id -> billing address). customer.support_rep_id is neither:
a customer is not their support rep.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from ..detect import KnownValues

COLUMN_KINDS = [
    ("secret", re.compile(r"password|passwd|_hash$|^hash$|token|api_?key|secret|^jwt$", re.I)),
    ("email", re.compile(r"e_?mail", re.I)),
    ("username", re.compile(r"^(user_?name|login|handle|screen_?name|nick(name)?|alias(es)?)$", re.I)),
    ("first_name", re.compile(r"^(first|given)_?name$", re.I)),
    ("last_name", re.compile(r"^(last|family|sur)_?name$", re.I)),
    ("name", re.compile(r"^(full_?|display_?|real_?|legal_?)?name$", re.I)),
    ("phone", re.compile(r"phone|mobile|^tel(ephone)?$|^fax$|^cell$", re.I)),
    ("ipv4", re.compile(r"(^|_)ip(_?addr(ess)?)?$", re.I)),        # before address: ip_address
    ("address", re.compile(r"^(?!.*(?:mac|ip|e_?mail|web|url)_?addr).*address(_?line_?\d)?$|^street", re.I)),
]
KINDS = {k for k, _ in COLUMN_KINDS}
IDENTITY_KINDS = {"email", "username", "name", "first_name", "last_name"}
LINK_KINDS = {"email", "username"}  # strong enough to merge records into one person
# Containers whose bare `name` is not a person (products, roles, ...).
PERSON_CONTAINERS = re.compile(
    r"user|account|member|customer|person|people|profile|contact|employee|author|patient|staff|client|tenant|"
    r"lead|subscriber|recipient|student|guest|applicant|candidate|driver|owner|buyer|seller|donor|volunteer|"
    r"attendee|participant|signup|registration|reviewer|commenter|actor|sender|assignee|reporter", re.I)
NAME_PARTS = {"given": "first_name", "first": "first_name", "firstname": "first_name",
              "family": "last_name", "last": "last_name", "lastname": "last_name", "surname": "last_name",
              "full": "name", "display": "name", "formatted": "name"}
GENERIC_LEAVES = {"number", "value", "raw", "text", "addr"}

# pg_anonymizer's identifier dictionary (PostgreSQL License), mapped selectively:
# opaque ids (`id`, `uid`, `client_id`) are deliberately NOT PII kinds for veil
# (pseudonymising them breaks code); dates are skipped for the same reason.
ANON_CATEGORY = {"email": "email", "firstname": "first_name", "phone_number": "phone", "fax_number": "phone",
                 "street_address": "address", "ip_address": "ipv4", "creditcard": "secret", "iban": "secret",
                 "social_security_id": "secret", "password": "secret"}
ANON_HANDLES = {"login", "username", "nom_utilisateur", "twitter", "twitter_id", "skype", "skype_id",
                "linkedin", "linkedin_id", "facebook", "facebook_id", "google", "ldap_id"}
ANON_NAMES = {"name": "name", "nom": "last_name", "last_name": "last_name"}


def _load_anon() -> dict[str, str]:
    path = os.path.join(os.path.dirname(__file__), "..", "data", "pg_anonymizer_identifier.csv")
    out: dict[str, str] = {}
    try:
        for line in open(path, encoding="utf-8"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            _, col, cat = parts
            kind = (ANON_CATEGORY.get(cat) or ("username" if cat == "account_id" and col in ANON_HANDLES else None)
                    or (ANON_NAMES.get(col) if cat == "name" else None))
            if kind:
                out[re.sub(r"[^a-z0-9]", "", col.lower())] = kind
    except OSError:
        pass
    return out


ANON_NAMES_DICT = _load_anon()

EMAIL_RE = re.compile(r"^[\w.%+-]+@[\w.-]+\.[^\W\d_]{2,}$")  # Unicode local parts (RFC 6531)
PHONE_RE = re.compile(r"^\+?[\d][\d\s().-]{6,22}$")
PHONE_SEP = re.compile(r"^\+|[\s().-]")  # bare digit runs are ids/timestamps, not phones


def _public_ip(v: str) -> bool:
    try:
        return ipaddress.ip_address(v.split("/")[0]).is_global
    except ValueError:
        return False


VALUE_RULES = [("email", lambda v: bool(EMAIL_RE.match(v))),
               ("phone", lambda v: bool(PHONE_RE.match(v)) and bool(PHONE_SEP.search(v))
                and sum(c.isdigit() for c in v) >= 7),
               ("ipv4", _public_ip)]


@dataclass
class Field:
    container: str
    path: str
    kind: str
    signal: str  # comment | name | values
    values: int = 0


@dataclass
class Report:
    fields: list[Field] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    added: int = 0

    def table(self) -> str:
        rows = [f"{f.container}.{f.path}".ljust(44) + f" {f.kind:<10} {f.signal:<8} {f.values:>6}" for f in self.fields]
        return "\n".join(["field".ljust(44) + " kind       signal   values", *rows,
                          f"{self.added} new known values"])


# -- paths ------------------------------------------------------------------

JWT_RE = re.compile(r"^eyJ[\w-]+\.(eyJ[\w-]+)\.[\w-]*$")
JWT_SEG = "$jwt"  # path segment: "decode this JWT's payload"


def _jwt_payload(v: Any) -> Any:
    m = JWT_RE.match(v) if isinstance(v, str) else None
    if not m:
        return None
    seg = m.group(1)
    try:
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except ValueError:
        return None


def flatten(obj: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Leaf (path, value) pairs; list items are addressed as `key[]`; JWT
    payloads (sessions, tokens) are opened as `key.$jwt.<claims>`."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from flatten(v, f"{prefix}[]")
    elif obj is not None:
        yield prefix, obj
        payload = _jwt_payload(obj)
        if isinstance(payload, dict):
            yield from flatten(payload, f"{prefix}.{JWT_SEG}")


def extract(record: dict, path: str) -> list[Any]:
    """All leaf values at `path` in a record (JSON strings and JWTs are opened)."""
    nodes = [record]
    for part in path.split("."):
        if part == JWT_SEG:
            nodes = [p for p in map(_jwt_payload, nodes) if p is not None]
            continue
        is_list = part.endswith("[]")
        key = part[:-2] if is_list else part
        nxt = []
        for n in nodes:
            if isinstance(n, str) and n[:1] in "{[":
                try:
                    n = json.loads(n)
                except ValueError:
                    continue
            if isinstance(n, dict) and key in n:
                v = n[key]
                if is_list and isinstance(v, list):
                    nxt.extend(v)
                elif not is_list:
                    nxt.append(v)
        nodes = nxt
    return [n for n in nodes if n is not None and not isinstance(n, (dict, list))]


def _singulars(word: str) -> list[str]:
    out = [word]
    if word.endswith("es") and len(word) > 4:
        out.append(word[:-2])
    if word.endswith("s") and not word.endswith("ss") and len(word) > 3:
        out.append(word[:-1])
    return out


def classify_name(container: str, path: str) -> str | None:
    parts = [p.removesuffix("[]") for p in path.split(".") if p != JWT_SEG]
    leaf, parent = parts[-1], (parts[-2] if len(parts) > 1 else None)
    if parent and parent.lower() in ("name", "names", "fullname", "full_name") and leaf.lower() in NAME_PARTS:
        return NAME_PARTS[leaf.lower()]
    candidates = _singulars(leaf)
    if parent and leaf.lower() in GENERIC_LEAVES:
        candidates = _singulars(parent) + candidates
    for word in candidates:
        for kind, rx in COLUMN_KINDS:
            if rx.search(word):
                # only a *bare* `name` needs a person-like container (products have names too)
                if kind == "name" and word.lower() == "name" and \
                        not PERSON_CONTAINERS.search(container + "." + ".".join(parts[:-1])):
                    return None
                return kind
    for word in candidates:  # secondary: pg_anonymizer dictionary (courriel, prenom, portable, ...)
        kind = ANON_NAMES_DICT.get(re.sub(r"[^a-z0-9]", "", word.lower()))
        if kind and not (kind == "name" and not PERSON_CONTAINERS.search(container)):
            return kind
    return None


ANON_FUNCS = [("email", r"email"), ("first_name", r"first_?name"), ("last_name", r"last_?name"),
              ("name", r"(?<!_)name"), ("phone", r"phone"), ("address", r"address|street"), ("ipv4", r"\bip"),
              ("secret", r"iban|siret|siren|credit|card|password|hash")]


def classify_label(label: str | None) -> str | None:
    """pg_anonymizer rule, e.g. "MASKED WITH FUNCTION anon.fake_email()" -> email.
    Any masking rule marks the column sensitive; the function name gives the kind."""
    if not label or "MASKED" not in label.upper():
        return None
    fn = label.lower()
    for kind, rx in ANON_FUNCS:
        if re.search(rx, fn):
            return kind
    return "pii"


def classify_comment(comment: str | None) -> str | None:
    """`pii:email`, `PII=phone`, `[pii: username] ...` -> kind; bare 'pii' -> 'pii'."""
    if not comment:
        return None
    m = re.search(r"\bpii\s*[:=]\s*([a-z_]+)", comment, re.I)
    if m and m.group(1).lower() in KINDS:
        return m.group(1).lower()
    return "pii" if re.search(r"\b(pii|personal data|gdpr)\b", comment, re.I) else None


def classify_values(values: Iterable[Any], threshold: float = 0.8, min_n: int = 5) -> str | None:
    vals = [str(v).strip() for v in values if isinstance(v, str) and str(v).strip()]
    if len(vals) < min_n:
        return None
    for kind, ok in VALUE_RULES:
        if sum(1 for v in vals if ok(v)) / len(vals) >= threshold:
            return kind
    return None


# -- planning & ingestion ---------------------------------------------------

@dataclass
class Container:
    """One table / collection, as a source describes it."""
    name: str
    key: str                                   # record field holding the primary key
    columns: dict[str, dict]                   # col -> {"json": bool, "comment": str|None}
    sample: list[dict]                         # a few hundred records for classification
    fks: dict[str, tuple[str, bool]] = field(default_factory=dict)  # col -> (target container, unique)


def plan(container: Container) -> list[Field]:
    """Decide which field paths hold PII, from comments, names and sampled values."""
    fields: list[Field] = []
    bare_names: list[str] = []
    for col, meta in container.columns.items():
        if col == container.key or col in container.fks:
            continue
        tagged = classify_comment(meta.get("comment"))
        paths: dict[str, list] = {}
        for rec in container.sample:
            v = rec.get(col)
            # declared JSON, or JSON hiding in a text type (MariaDB JSON = LONGTEXT)
            if isinstance(v, str) and (meta.get("json") or v[:1] in "{["):
                try:
                    v = json.loads(v)
                except ValueError:
                    pass
            for p, leaf in flatten(v, col):
                paths.setdefault(p, []).append(leaf)
        if not paths:
            paths = {col: []}
        for p, samples in paths.items():
            if tagged and tagged != "pii" and p == col:
                fields.append(Field(container.name, p, tagged, "comment"))
                continue
            kind = classify_name(container.name, p)
            if kind:
                fields.append(Field(container.name, p, kind, "name"))
                continue
            kind = classify_values(samples)
            if kind:
                fields.append(Field(container.name, p, kind, "comment+values" if tagged else "values"))
            elif p.split(".")[-1].removesuffix("[]").lower() == "name":
                bare_names.append(p)
    # A bare `name` next to an email/username in the same record is a person's name,
    # whatever the container is called (export.json, items, ...).
    if any(f.kind in LINK_KINDS for f in fields):
        fields += [Field(container.name, p, "name", "name+context") for p in bare_names]
    return fields


def is_person(fields: list[Field]) -> bool:
    return any(f.kind in IDENTITY_KINDS for f in fields)


class Seeder:
    """Feeds planned fields of every container into KnownValues with groups."""

    def __init__(self, known: KnownValues):
        self.known = known
        self.report = Report()
        self.person_group: dict[str, dict[Any, str]] = {}  # container -> key value -> group

    def order(self, containers: list[Container], plans: dict[str, list[Field]]) -> list[Container]:
        """FK targets before referrers, so persons are seeded first (first source wins)."""
        done, out = set(), []

        def visit(c: Container, stack=()):
            if c.name in done or c.name in stack:
                return
            for target, _ in c.fks.values():
                t = next((x for x in containers if x.name == target), None)
                if t:
                    visit(t, stack + (c.name,))
            done.add(c.name)
            out.append(c)
        # persons first, and among them person-named containers (users before comments)
        for c in sorted(containers, key=lambda c: (not is_person(plans[c.name]),
                                                   not PERSON_CONTAINERS.search(c.name.split(".")[-1]))):
            visit(c)
        return out

    def ingest(self, container: Container, fields: list[Field], records: Iterable[dict]) -> None:
        own_identity = is_person(fields)
        links = [(col, target) for col, (target, unique) in container.fks.items()
                 if target in self.person_group and (unique or not own_identity)]
        groups = self.person_group.setdefault(container.name, {}) if own_identity or links else None
        before = len(self.known)
        strong = [f for f in fields if f.kind in LINK_KINDS]
        for rec in records:
            key = rec.get(container.key)
            if isinstance(key, (dict, list)):
                key = json.dumps(key, sort_keys=True, default=str)
            group = f"{container.name}:{key}"
            for col, target in links:
                linked = self.person_group[target].get(rec.get(col))
                if linked:
                    group = linked
                    break
            else:
                # No FK: join an already-known person when an email/username matches
                # (denormalised copies, other stores). Never on names: homonyms.
                for f in strong:
                    hit = next((self.known.group_of(str(v)) for v in extract(rec, f.path)
                                if self.known.group_of(str(v))), None)
                    if hit:
                        group = hit
                        break
            if groups is not None:
                groups[key] = group
            parts: dict[str, str] = {}
            for f in fields:
                for v in extract(rec, f.path):
                    v = str(v)
                    n = len(self.known)
                    self.known.add(v, f.kind if f.kind != "pii" else "secret", group)
                    f.values += len(self.known) - n
                    parts.setdefault(f.kind, v)
            # "Leonie Köhler" shows up in logs and prose more than either half alone
            if parts.get("first_name") and parts.get("last_name"):
                self.known.add(f"{parts['first_name']} {parts['last_name']}", "name", group)
        self.report.fields += fields
        self.report.added += len(self.known) - before
