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

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from .match import Matcher

WORD = r"A-Za-z0-9_"
def _load_words() -> frozenset[str]:
    """Lower-case common words (macOS/Linux /usr/share/dict/words; lower-case entries only,
    so proper names like 'Jennifer' or 'Hansen' are not in it)."""
    for path in ("/usr/share/dict/words", "/usr/dict/words"):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return frozenset(w.strip() for w in f if w.strip().islower())
        except OSError:
            continue
    return frozenset()


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


PATTERNS: list[tuple[str, re.Pattern, object]] = [
    # \w is Unicode-aware: internationalised addresses (RFC 6531) like luís.gonçalves@x.net
    ("email", re.compile(r"(?<![\w.+-])[\w.%+-]+@[\w.-]+\.[^\W\d_]{2,}(?![\w-])"),
     lambda v: not ALLOWED_EMAIL_DOMAINS.search(v) and not ALLOWED_EMAIL_LOCALS.search(v)),
    ("phone", re.compile(r"(?<![\w+])(?:\+?\d{1,3}[ .-])?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"),
     None),
    # a trailing "." ends a sentence unless a digit follows (1.2.3.4.5 is not an IP)
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)"), _public_ip),
    ("card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
     lambda v: _luhn(re.sub(r"\D", "", v))),
    ("secret", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9_]{16,}"
        r"|whsec_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}"
        r"|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,})"), None),
]


class KnownValues:
    """Exact-match dictionary of real values (prototype: one big regex).

    Production should use Aho-Corasick; Python's re alternation is fine for a
    few tens of thousands of values.
    """

    def __init__(self, min_len: int = 4):
        self.min_len = min_len
        self._entries: dict[str, tuple[str, str | None]] = {}
        self._aliases: dict[str, str] = {}  # encoded/normalised form -> canonical value
        self._emails_ci: dict[str, str] = {}  # casefolded email -> canonical (emails are case-insensitive)
        self._pattern: Matcher | None = None
        self._email_pattern: Matcher | None = None

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
        for alias in encoded_forms(value, kind):
            self._aliases.setdefault(alias, value)
        if kind == "email":
            self._emails_ci.setdefault(value.lower(), value)
            # The local part identifies the person on its own: `jane.roe at mailbox dot org`,
            # substr() splits, usernames equal to it. Role mailboxes are not people.
            local = value.split("@")[0]
            if len(local) >= 5 and not local.isdigit() and local.lower() not in ROLE_LOCALS:
                self.add(local, "username", group)
        self._pattern = None

    def copy(self) -> "KnownValues":
        """Cheap copy (no re-derivation) for build-then-swap updates."""
        new = KnownValues(self.min_len)
        new._entries, new._aliases, new._emails_ci = dict(self._entries), dict(self._aliases), dict(self._emails_ci)
        return new

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
            self._pattern = Matcher([*self._entries, *self._aliases])
            self._email_pattern = Matcher(self._emails_ci) if self._emails_ci else None
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
    spans: list[Span] = (list(known.find(text)) if known else []) + list(extra or [])
    for kind, pattern, check in PATTERNS:
        for m in pattern.finditer(text):
            v = m.group()
            if check is None or check(v):
                spans.append(Span(m.start(), m.end(), kind, v))
    # Longest span wins; ties go to higher priority (known values).
    spans.sort(key=lambda s: (-(s.end - s.start), -s.priority, s.start))
    taken: list[Span] = []
    for s in spans:
        if is_token(s.value) or (ALLOW and s.value.lower() in ALLOW):
            continue
        if all(s.end <= t.start or s.start >= t.end for t in taken):
            taken.append(s)
    return sorted(taken, key=lambda s: s.start)
