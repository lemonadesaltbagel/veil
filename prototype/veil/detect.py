"""PII span detection.

Layers, highest priority first:
  1. Known values  - exact strings seeded from the developer's own data source
                     (e.g. every users.email). Near-perfect recall for the data
                     that actually matters, no ML, works inside code/logs/JSON.
  2. Pattern rules - emails, phones, IPs, cards (Luhn), common secret formats.
  3. (not in prototype) NER for free text, e.g. Presidio / GLiNER.
Allowlists drop reserved/test values; existing tokens are never re-redacted.
"""

from __future__ import annotations

import bisect
import ipaddress
import itertools
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from .match import Matcher

WORD = r"A-Za-z0-9_"
def _load_words() -> frozenset[str]:
    """Lower-case common English words (Webster's Second, public domain; vendored so every
    platform filters the same: Linux runners and Windows have no /usr/share/dict/words).
    Lower-case entries only, so proper names like 'Jennifer' or 'Hansen' are not in it."""
    import gzip
    path = os.path.join(os.path.dirname(__file__), "data", "words.txt.gz")
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return frozenset(w for w in f.read().split("\n") if w)


COMMON_WORDS = _load_words()
# Values a team declares are never PII (support@company.com, product names). Set by state.load().
ALLOW: set[str] = set()


def set_allowlist(values) -> None:
    ALLOW.clear()
    ALLOW.update(v.strip().lower() for v in values if v and v.strip())
# A standalone name part that is also a common word (Code, Read, Mark, Silk, Will) would rewrite
# ordinary text ("Claude Code", the Read tool). The full name ("Ann Code") is still seeded.
WORD_FILTERED_KINDS = {"first_name", "last_name", "username"}

ROLE_LOCALS = {"info", "sales", "support", "contact", "admin", "hello", "office", "billing", "noreply",
               "no-reply", "team", "help", "service", "accounts", "marketing", "press", "jobs", "careers",
               "security", "privacy", "legal", "webmaster", "postmaster", "abuse", "mailer-daemon", "notifications"}
STOPWORDS = {
    "admin", "root", "test", "user", "guest", "demo", "null", "none", "true",
    "false", "name", "email", "support", "info", "system", "default", "public",
}
# Role/system senders that identify no person (users.noreply.github.com does: not here).
ALLOWED_EMAIL_LOCALS = re.compile(r"^(?:no-?reply|do-?not-?reply|mailer-daemon|postmaster)@(?!users\.noreply\.)", re.I)
ALLOWED_EMAIL_DOMAINS = re.compile(
    r"@(?:[\w.-]+\.)?(?:example\.(?:com|org|net)|[\w-]+\.(?:test|invalid|example|localhost))$",
    re.I,
)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    value: str
    group: str | None = None
    priority: int = 0


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


def _public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_global


def _iban(v: str) -> bool:
    v = v.replace(" ", "")
    if not 15 <= len(v) <= 34:
        return False
    digits = "".join(str(int(ch, 36)) for ch in v[4:] + v[:4])
    return int(digits) % 97 == 1


PATTERNS: list[tuple[str, re.Pattern, object]] = [
    # \w is Unicode-aware: internationalised addresses (RFC 6531) like luís.gonçalves@x.net
    ("email", re.compile(r"(?<![\w.+-])[\w.%+-]+@[\w.-]+\.[^\W\d_]{2,}(?![\w-])"),
     lambda v: not ALLOWED_EMAIL_DOMAINS.search(v) and not ALLOWED_EMAIL_LOCALS.search(v)),
    ("phone", re.compile(r"(?<![\w+])(?:\+?\d{1,3}[ .-])?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"),
     None),
    # a trailing "." ends a sentence unless a digit follows (1.2.3.4.5 is not an IP)
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"), _public_ip),
    # US SSN (never-issued ranges excluded); IBAN with its mod-97 checksum
    ("id_number", re.compile(r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])"), None),
    ("id_number", re.compile(r"(?<![\w])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?!\w)"), _iban),
    ("card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
     lambda v: _luhn(re.sub(r"\D", "", v))),
    ("secret", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9_]{16,}"
        r"|whsec_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}"
        r"|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,})"), None),
]


class KnownValues:
    """Exact-match dictionary of real values and their encoded forms (anchored
    Aho-Corasick, see match.py; shared with the outbound guard)."""

    def __init__(self, min_len: int = 4):
        self.min_len = min_len
        self._entries: dict[str, tuple[str, str | None]] = {}
        self._aliases: dict[str, str] = {}  # encoded/normalised form -> canonical value
        self._emails_ci: dict[str, str] = {}  # casefolded email -> canonical (emails are case-insensitive)
        self._pattern: Matcher | None = None
        self._email_pattern: Matcher | None = None
        # quasi-identifiers (city, postal code, birth date, company, job title): value ->
        # [kind, number of records with it, group]. Only rare ones identify anyone.
        self._quasi: dict[str, list] = {}
        self._quasi_pattern: Matcher | None = None
        # who has each quasi value (person ids), for combinations: city + job title can be
        # unique even when each is common. Counts are intersections, computed on demand.
        self._qi_people: dict[str, set[int]] = {}
        self._qi_groups: dict[str, int] = {}
        self._qi_all: Matcher | None = None
        self._combo_cache: dict[frozenset, int] = {}
        # incremental indexes: a copy remembers its parent's built matchers and the needles
        # added since, so a re-seed that adds a few values doesn't rebuild everything
        self._base_pattern: Matcher | None = None
        self._base_email: Matcher | None = None
        self._new_needles: list[str] = []
        self._new_emails: list[str] = []
        self._new_values: list[str] = []
        self._base_guard = None

    def add(self, value: str, kind: str, group: str | None = None) -> None:
        value = value.strip()
        if not value or value.lower() in STOPWORDS or value.lower() in ALLOW:
            return
        if kind != "email" and len(value) < self.min_len:
            return
        if kind in WORD_FILTERED_KINDS and " " not in value and value.lower() in COMMON_WORDS:
            return
        if value in self._entries:  # first source wins: keeps a person's group when
            return                  # the value is repeated elsewhere (e.g. BillingAddress)
        self._entries[value] = (kind, group)
        self._new_needles.append(value)
        self._new_values.append(value)
        for alias in encoded_forms(value, kind):
            if self._aliases.setdefault(alias, value) == value:
                self._new_needles.append(alias)
        if kind == "email":
            if self._emails_ci.setdefault(value.lower(), value) == value:
                self._new_emails.append(value.lower())
            # The local part identifies the person on its own: `jane.roe at mailbox dot org`,
            # substr() splits, usernames equal to it. Role mailboxes are not people.
            local = value.split("@")[0]
            if len(local) >= 5 and not local.isdigit() and local.lower() not in ROLE_LOCALS:
                self.add(local, "username", group)
        if self._pattern is not None:  # built already: grow from it next time instead of rebuilding
            self._base_pattern, self._base_email = self._pattern, self._email_pattern
            self._pattern = None

    def copy(self) -> "KnownValues":
        """Cheap copy (no re-derivation) for build-then-swap updates."""
        new = KnownValues(self.min_len)
        new._entries, new._aliases, new._emails_ci = dict(self._entries), dict(self._aliases), dict(self._emails_ci)
        new._quasi = {v: list(x) for v, x in self._quasi.items()}
        new._qi_people = {v: set(p) for v, p in self._qi_people.items()}
        new._qi_groups = dict(self._qi_groups)
        new._base_pattern, new._base_email = self._pattern, self._email_pattern
        new._base_guard = getattr(self, "_guard_index", None)
        return new

    # -- quasi-identifiers ---------------------------------------------------
    def add_quasi(self, value, kind: str, group: str | None = None) -> None:
        value = str(value).strip()
        if kind == "dob":
            value = value.removesuffix(" 00:00:00").removesuffix("T00:00:00")
        if len(value) < 4 or value.lower() in STOPWORDS or value.lower() in ALLOW or value in self._entries:
            return
        entry = self._quasi.get(value)
        if entry is None:
            entry = self._quasi[value] = [kind, 0, group]
        if group is not None:
            people = self._qi_people.setdefault(value, set())
            people.add(self._qi_groups.setdefault(group, len(self._qi_groups)))
            entry[1] = len(people)
        else:
            entry[1] += 1
        self._quasi_pattern = self._qi_all = None
        self._combo_cache.clear()

    def rare_quasi(self) -> dict[str, list]:
        """Quasi-identifiers shared by fewer than QUASI_K records (k-anonymity). Dictionary
        words ("Nice", "Mobile", "Engineer") are left to combinations: alone they'd match
        ordinary text."""
        return {v: e for v, e in self._quasi.items() if e[1] < QUASI_K
                and not (e[0] in ("city", "company", "job_title") and v.lower() in COMMON_WORDS)}

    def find_quasi(self, text: str) -> list[Span]:
        if not self._quasi:
            return []
        if self._quasi_pattern is None:
            self._quasi_pattern = Matcher(self.rare_quasi())
        return [Span(a, b, self._quasi[n][0], n, self._quasi[n][2], priority=5)
                for a, b, n in self._quasi_pattern.find(text)]

    def combo_count(self, values) -> int:
        """How many people have all these quasi values."""
        key = frozenset(values)
        if key not in self._combo_cache:
            sets = sorted((self._qi_people.get(v, set()) for v in key), key=len)
            self._combo_cache[key] = len(set.intersection(*sets)) if sets else 0
        return self._combo_cache[key]

    def quasi_combos(self, text: str, max_values: int = 8) -> list[tuple[list[Span], int]]:
        """Combinations of quasi values on one line (2-3 different kinds) that fewer than
        QUASI_K people share: identifying together, though each value may be common."""
        if not self._qi_people:
            return []
        if self._qi_all is None:
            self._qi_all = Matcher(self._quasi)
        out, base = [], 0
        for line in text.split("\n"):
            hits = {}
            for a, b, n in self._qi_all.find(line):
                hits.setdefault(n, Span(base + a, base + b, self._quasi[n][0], n, None, priority=5))
            base += len(line) + 1
            if len({s.kind for s in hits.values()}) < 2:
                continue
            # values rare on their own are reported/redacted individually; combinations are
            # about values that are common alone (or dictionary words, never matched alone)
            spans = [s for s in hits.values() if self._quasi[s.value][1] >= QUASI_K
                     or (s.kind in ("city", "company", "job_title") and s.value.lower() in COMMON_WORDS)][:max_values]
            found = set()
            for size in (2, 3):
                for combo in itertools.combinations(spans, size):
                    if len({s.kind for s in combo}) < size or any(set(c) <= set(combo) for c in found):
                        continue
                    n = self.combo_count(s.value for s in combo)
                    if 0 < n < QUASI_K:
                        found.add(combo)
                        out.append((list(combo), n))
        return out

    def group_of(self, s: str) -> str | None:
        value = self.canonical(s.strip())
        return self._entries[value][1] if value else None

    def canonical(self, s: str) -> str | None:
        if s in self._entries:
            return s
        return self._aliases.get(s) or self._emails_ci.get(s.lower())

    def __len__(self) -> int:
        return len(self._entries)

    def matcher(self) -> Matcher:
        """Every seeded value and encoded form (shared with the outbound guard)."""
        if self._pattern is None:
            if self._base_pattern is not None and len(self._new_needles) < max(1000, len(self._entries) // 10):
                self._pattern = self._base_pattern.copy_with(self._new_needles)  # a few new values: grow a copy
                self._email_pattern = (self._base_email.copy_with(self._new_emails) if self._base_email
                                       else Matcher(self._emails_ci) if self._emails_ci else None)
            else:
                self._pattern = Matcher([*self._entries, *self._aliases])
                self._email_pattern = Matcher(self._emails_ci) if self._emails_ci else None
            self._base_pattern = self._base_email = None
            self._new_needles, self._new_emails = [], []
        return self._pattern

    def find(self, text: str) -> list[Span]:
        if not self._entries:
            return []
        self.matcher()
        out = []
        found = [(a, b, n) for a, b, n in self._pattern.find(text)]
        if self._email_pattern is not None:  # case variants of known emails
            low = text.lower()
            if len(low) == len(text):  # lower() kept offsets (true for almost all text)
                found += [(a, b, text[a:b]) for a, b, _ in self._email_pattern.find(low)
                          if (a == 0 or text[a - 1] not in ".+-") and (b == len(text) or text[b] != "-")]
        for start, end, needle in found:
            value = self.canonical(needle)
            kind, group = self._entries[value]
            out.append(Span(start, end, kind, value, group, priority=10))
        return out


QUASI_K = 5  # a value shared by fewer records than this points at a few people
QUASI_KINDS = ("dob", "postal_code", "city", "company", "job_title")


def encoded_forms(value: str, kind: str) -> set[str]:
    """Other spellings of the same value that show up in developer artifacts:
    URL query strings, JSON dumped with ensure_ascii, macOS NFD filenames,
    lower-cased emails in logs."""
    forms = {
        json.dumps(value)[1:-1],                    # K\u00f6hler, escaped quotes
        quote(value, safe=""), quote_plus(value),   # jane.roe%40mailbox.org, Jos%C3%A9+Mu%C3%B1oz
        unicodedata.normalize("NFD", value), unicodedata.normalize("NFC", value),
    }
    if kind == "email":  # plain case variants are matched case-insensitively instead
        forms |= {quote(value.lower(), safe=""), quote(value.upper(), safe="")}
    forms.discard(value)
    return {f for f in forms if f}


def detect(text: str, known: KnownValues | None, is_token, extra: list[Span] | None = None) -> list[Span]:
    spans: list[Span] = (list(known.find(text)) if known is not None else []) + list(extra or [])
    for kind, pattern, check in PATTERNS:
        for m in pattern.finditer(text):
            v = m.group()
            if check is None or check(v):
                spans.append(Span(m.start(), m.end(), kind, v))
    # Longest span wins; ties go to higher priority (known values).
    spans.sort(key=lambda s: (-(s.end - s.start), -s.priority, s.start))
    taken: list[Span] = []  # kept sorted by start: overlap = a neighbour check (was a scan of all)
    starts: list[int] = []
    for s in spans:
        if is_token(s.value) or (ALLOW and s.value.lower() in ALLOW):
            continue
        i = bisect.bisect_left(starts, s.start)
        if (i > 0 and taken[i - 1].end > s.start) or (i < len(taken) and taken[i].start < s.end):
            continue
        starts.insert(i, s.start)
        taken.insert(i, s)
    return taken
