"""Outbound guard: an independent last check on the exact request about to leave.

The redaction pass decides *where* to look (fields, block types). Both leaks the
mock tests found were "didn't look there" bugs (an unknown top-level field, an
uncovered key format). The guard doesn't care about structure: it walks every
string in the final body and looks for

  * every real value veil knows (seeded + everything redacted so far), in plain
    and encoded forms (URL, JSON-escaped, NFD, base64 at all 3 alignments);
  * pattern-detectable PII (emails, phones, cards, keys) anywhere outside
    signed thinking blocks.

Findings are repaired in place (value -> its token) when that is safe; findings
that can't be repaired (inside signed thinking) block the request. The audit
record names the field path, kind and token -- never the real value.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

from .decode import norm, squash, strong_views, views
from .detect import WORD, detect, encoded_forms
from .engine import Veil
from .match import Matcher

UNREPAIRABLE = ("thinking", "signature", "redacted_thinking")
WITHHELD = ("[veil: output withheld - it contained personal data in an escaped/encoded form "
            "(e.g. sed -n l, octal or \\x escapes). Read the data normally; values are pseudonymised.]")
PATTERN_KINDS = {"email", "phone", "ipv4", "card", "secret"}
# Protocol structure, never content: a seeded last name "Read" must not rename the Read tool.
STRUCTURAL = {"type", "id", "tool_use_id", "role", "cache_control", "media_type", "signature"}
TOOL_BLOCKS = {"tool_use", "server_tool_use", "mcp_tool_use", "tool_reference"}
TRUNCATABLE = {"name", "first_name", "last_name", "email", "username", "address", "secret"}
PARTIAL = "[veil:partial]"
# Deliberately independent of the redactor's CONFIG_FIELDS: the guard must not
# share the redactor's assumptions. Only scalar settings are skipped (a model id
# that happens to equal a known value must not be "repaired").
SCALAR_SETTINGS = {"model", "max_tokens", "stream", "temperature", "top_p", "top_k", "service_tier"}


@dataclass
class Finding:
    path: str
    kind: str
    form: str  # plain | encoded | base64 | pattern
    token: str
    repaired: bool = False
    # Model-written thinking can't be edited (signed). Real values there were produced
    # by the provider itself, so forwarding adds nothing new: allow, but report loudly
    # (it means an earlier leak, or a coincidence like a common first name).
    allowed: bool = False


def _b64_forms(value: str) -> set[str]:
    """Substrings that appear in base64 of any text containing `value`,
    whatever its byte offset (3 alignments, edge chars that mix with
    neighbours trimmed)."""
    raw = value.encode()
    out = set()
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw).decode().rstrip("=")
        start = (0, 2, 3)[k]
        core = enc[start:len(enc) - 2]
        if len(core) >= 8:
            out.add(core)
    return out


class _Index:
    """All needle structures for one set of real values."""

    def __init__(self, values: dict[str, str]):
        needles: dict[str, tuple[str, str, str]] = {}
        for value, kind in values.items():
            if len(value) < 4 and kind != "email":
                continue
            needles.setdefault(value, (value, kind, "plain"))
            for f in encoded_forms(value, kind):
                needles.setdefault(f, (value, kind, "encoded"))
            if len(value) >= 6:
                for f in _b64_forms(value):
                    needles.setdefault(f, (value, kind, "base64"))
        self.needles = needles
        # base64 fragments sit inside runs of [A-Za-z0-9+/], so no word boundaries for them
        self.matchers = [Matcher([n for n, (_, _, f) in needles.items() if f != "base64"]),
                         Matcher([n for n, (_, _, f) in needles.items() if f == "base64"], bounded=False)]
        # transformed copies (UPPER, s p a c e d, reversed, rot13, hex, url) of values >= 8 chars
        # mode 'w': word view (spaces kept); mode 'c': character view (spaces removed)
        self.norm_values: dict[str, dict[str, tuple[str, str]]] = {"w": {}, "c": {}}
        for value, kind in values.items():
            if len(squash(value)) >= 8:
                self.norm_values["w"].setdefault(norm(value), (value, kind))
                self.norm_values["c"].setdefault(squash(value), (value, kind))
        self.norm = {m: Matcher(list(v), bounded=False) for m, v in self.norm_values.items()}
        # Truncated values (cut -c, substr, fixed-width columns): a value's head ending
        # exactly at a line end, or its tail starting exactly at a line start.
        self.heads, self.tails = {}, {}
        for value, kind in values.items():
            if len(value) >= 8 and kind in TRUNCATABLE:
                for k in range(6, len(value)):
                    self.heads.setdefault(value[:k], (value, kind))
                    self.tails.setdefault(value[-k:], (value, kind))
        self.partial = [Matcher(list(self.heads), bounded=False), Matcher(list(self.tails), bounded=False)]


class Guard:
    def __init__(self, veil: Veil):
        self.veil = veil
        self._seeded: _Index | None = None   # big, rebuilt only when seeding changes
        self._seeded_key = None
        self._found: _Index | None = None    # small: pattern-found values, rebuilt per new token
        self._found_key = None

    def _build(self) -> list[_Index]:
        # Strong sources only: seeded values, and values that patterns detect anywhere.
        # NER guesses are redacted where they occur but never become global needles
        # (a mis-tagged "Claude Code" would otherwise be rewritten in system prompts).
        known = self.veil.known._entries
        if self._seeded_key != len(known):
            self._seeded = _Index({v: k for v, (k, _) in known.items()})
            self._seeded_key = len(known)
        if self._found_key != (len(known), self.veil.vault.version):
            self._found = _Index({value: kind for (kind, value) in self.veil.vault._by_value
                                  if kind in PATTERN_KINDS and value not in known})
            self._found_key = (len(known), self.veil.vault.version)
        return [self._seeded, self._found]

    @property
    def _needles(self):  # introspection (benchmarks/tests)
        return {**self._seeded.needles, **self._found.needles} if self._seeded else {}

    def _token(self, value: str, kind: str) -> str:
        entry = self.veil.known._entries.get(value)
        group = entry[1] if entry else None
        return self.veil.vault.token_for(kind, value, group)

    def enforce(self, body: Any) -> tuple[Any, list[Finding]]:
        """Return (repaired body, findings). Any finding with repaired=False
        means the request must not be sent."""
        self._indexes = self._build()
        findings: list[Finding] = []
        if isinstance(body, dict):  # scalar request settings are not content
            body = {k: (v if k in SCALAR_SETTINGS else self._walk(v, k, findings, in_thinking=False))
                    for k, v in body.items()}
        else:
            body = self._walk(body, "", findings, in_thinking=False)
        return body, findings

    def _walk(self, node: Any, path: str, findings: list[Finding], in_thinking: bool) -> Any:
        if isinstance(node, dict):
            t = node.get("type")
            t = t if isinstance(t, str) else None  # JSON Schema: a property may be *named* "type"
            thinking = in_thinking or t in UNREPAIRABLE
            tool_like = t in TOOL_BLOCKS or "input_schema" in node
            return {k: (v if k in STRUCTURAL or (k == "name" and tool_like)
                        else self._walk(v, f"{path}.{k}", findings, thinking or k == "signature"))
                    for k, v in node.items()}
        if isinstance(node, list):
            return [self._walk(v, f"{path}[{i}]", findings, in_thinking) for i, v in enumerate(node)]
        if isinstance(node, str):
            return self._check(node, path.lstrip("."), findings, in_thinking)
        return node

    def _check(self, s: str, path: str, findings: list[Finding], frozen: bool) -> str:
        indexes = self._indexes
        # Heuristic checks (transformed / truncated values) only where data flows in:
        # messages. The agent's own system prompt and tool schemas are instructions,
        # where a false positive would break the agent.
        content = path.startswith("messages")
        # Values hidden by a transform can't be repaired in place: withhold the whole
        # string. (1) case, spacing, reversal, rot13, hex, url  (2) escapes/line wrapping.
        if content and len(s) >= 8:
            for mode, view in strong_views(s):
                for ix in indexes:
                    for _, _, n in ix.norm[mode].find(view):
                        value, kind = ix.norm_values[mode][n]
                        if value in s:
                            continue  # verbatim: the plain pass below repairs it in place
                        findings.append(Finding(path, kind, "transformed", "[withheld]",
                                                repaired=not frozen, allowed=frozen))
                        return s if frozen else WITHHELD
        for view in views(s):
            for ix in indexes:
                hidden = [n for _, _, n in ix.matchers[0].find(view) if n not in s]
                if hidden:
                    value, kind, _ = ix.needles[hidden[0]]
                    findings.append(Finding(path, kind, "escaped", "[withheld]", repaired=not frozen, allowed=frozen))
                    return s if frozen else WITHHELD
        hits: list[tuple[int, int, str, str, str]] = []  # start, end, replacement, kind, form
        for ix in indexes:
            for matcher in ix.matchers:
                for start, end, needle in matcher.find(s):
                    value, kind, form = ix.needles[needle]
                    tok = self._token(value, kind)
                    hits.append((start, end, "[veil:base64-redacted]" if form == "base64" else tok, kind, form))
        if content and not frozen and ("\n" in s or "\ufffd" in s):
            pattern = self.veil.token_pattern()
            tokens = [(m.start(), m.end()) for m in pattern.finditer(s)] if pattern else []
            # U+FFFD: a byte-wise cut (GNU `cut -b`, head -c) split a UTF-8 character
            line_end = lambda i: i == len(s) or s[i] in "\r\n\ufffd"
            line_start = lambda i: i == 0 or s[i - 1] in "\n\ufffd"
            word = lambda c: c.isalnum() or c == "_"
            for ix in indexes:
                for which, matcher in zip(("head", "tail"), ix.partial):
                    table = ix.heads if which == "head" else ix.tails
                    for a, b, n in matcher.find(s):
                        ok = (line_end(b) and (a == 0 or not word(s[a - 1]))) if which == "head" else \
                             (line_start(a) and (b == len(s) or not word(s[b])))
                        # never inside veil's own tokens ("Ab12 Example Street" vs a surname "Streeting")
                        if ok and table[n][0] not in s and not any(x < b and a < y for x, y in tokens) \
                                and not any(x < b and a < y for x, y, *_ in hits):
                            hits.append((a, b, PARTIAL, table[n][1], "partial"))
        if not frozen:
            for span in detect(s, None, self.veil.vault.is_token):
                if not any(a < span.end and span.start < b for a, b, *_ in hits):
                    tok = self.veil.vault.token_for(span.kind, span.value)
                    hits.append((span.start, span.end, tok, span.kind, "pattern"))
        if not hits:
            return s
        hits.sort()
        out, pos = [], 0
        for start, end, repl, kind, form in hits:
            findings.append(Finding(path, kind, form, repl, repaired=not frozen, allowed=frozen))
            if start >= pos:
                out += [s[pos:start], repl]
                pos = end
        out.append(s[pos:])
        return s if frozen else "".join(out)
