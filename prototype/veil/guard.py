"""Outbound guard: an independent last check on the exact request about to leave.

The redaction pass decides *where* to look (fields, block types). Both leaks the
mock tests found were "didn't look there" bugs (an unknown top-level field, an
uncovered key format). The guard doesn't care about structure: it walks every
string in the final body and looks for

  * every real value veil knows (seeded + everything redacted so far), in plain
    and encoded forms (URL, JSON-escaped, NFD; base64 runs are decoded at every alignment);
  * pattern-detectable PII (emails, phones, cards, keys) anywhere outside
    signed thinking blocks.

Findings are repaired in place (value -> its token) when that is safe; findings
that can't be repaired (inside signed thinking) block the request. The audit
record names the field path, kind and token -- never the real value.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Any

from .decode import b64_runs, norm, squash, strong_views, views
from .detect import detect, encoded_forms
from .engine import Veil
from .match import Matcher, Prefixes

UNREPAIRABLE = ("thinking", "signature", "redacted_thinking")
WITHHELD = ("[veil: output withheld - it contained personal data in an escaped/encoded form "
            "(e.g. sed -n l, octal or \\x escapes). Read the data normally; values are pseudonymised.]")
PATTERN_KINDS = {"email", "phone", "ipv4", "card", "secret", "id_number"}
# Protocol structure, never content: a seeded last name "Read" must not rename the Read tool.
STRUCTURAL = {"type", "id", "tool_use_id", "role", "cache_control", "media_type", "signature"}
TOOL_BLOCKS = {"tool_use", "server_tool_use", "mcp_tool_use", "tool_reference"}
TRUNCATABLE = {"name", "first_name", "last_name", "email", "username", "address", "secret", "id_number"}
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


class _Index:
    """All needle structures for one set of real values. The seeded index shares the
    redactor's dictionary matcher (same values, same encoded forms: building a second
    copy doubled memory); the guard stays independent in *where* it looks."""

    def __init__(self, values: dict[str, str] | None = None, known=None):
        if known is not None:
            self.plain = known.matcher()
            self.kind_of = lambda v: known._entries[v][0]
            self._canonical = known.canonical
            items = [(v, k) for v, (k, _) in known._entries.items()]
        else:
            values = {v: k for v, k in values.items() if len(v) >= 4 or k == "email"}
            aliases = {}
            for value, kind in values.items():
                for f in encoded_forms(value, kind):
                    aliases.setdefault(f, value)
            self.plain = Matcher([*values, *aliases])
            self.kind_of = values.__getitem__
            self._canonical = lambda n: n if n in values else aliases.get(n)
            items = list(values.items())
        # transformed copies (UPPER, s p a c e d, reversed, rot13, hex, url) of values >= 8 chars
        # mode 'w': word view (spaces kept); mode 'c': character view (spaces removed)
        self.norm_values: dict[str, dict[str, str]] = {"w": {}, "c": {}}
        for value, kind in items:
            if len(squash(value)) >= 8:
                w, c = norm(value), squash(value)
                w = value if w == value else w  # share the string (most emails, usernames)
                self.norm_values["w"].setdefault(w, value)
                self.norm_values["c"].setdefault(w if c == w else c, value)
        # one automaton for both views (single-word values have the same needle in each)
        both = Matcher([*self.norm_values["w"], *self.norm_values["c"]], bounded=False)
        self.norm = {"w": both, "c": both}
        # Truncated values (cut -c, substr, fixed-width columns): a value's head ending
        # exactly at a line end, or its tail starting exactly at a line start.
        cut = [v for v, kind in items if len(v) >= 8 and kind in TRUNCATABLE]
        self.heads, self.tails = Prefixes(cut), Prefixes(cut, reverse=True)
        self.tail_anchors = Matcher([v[-6:][::-1] for v in cut], bounded=False)  # reversed text
        self.longest = max(map(len, cut), default=0)

    @classmethod
    def grown(cls, base: "_Index", known, values: list[str]) -> "_Index":
        """`base` plus a few new seeded values, without rebuilding (copy-on-write: `base`
        may still be serving requests)."""
        ix = cls.__new__(cls)
        ix.plain = known.matcher()
        ix.kind_of = lambda v: known._entries[v][0]
        ix._canonical = known.canonical
        ix.norm_values = {m: dict(d) for m, d in base.norm_values.items()}
        needles = []
        for value in values:
            if len(squash(value)) >= 8:
                w, c = norm(value), squash(value)
                w = value if w == value else w
                ix.norm_values["w"].setdefault(w, value)
                ix.norm_values["c"].setdefault(w if c == w else c, value)
                needles += [w, c]
        both = base.norm["w"].copy_with(needles)
        ix.norm = {"w": both, "c": both}
        cut = [v for v in values if len(v) >= 8 and known._entries[v][0] in TRUNCATABLE]
        ix.heads, ix.tails = base.heads.with_values(cut), base.tails.with_values(cut)
        ix.tail_anchors = base.tail_anchors.copy_with([v[-6:][::-1] for v in cut])
        ix.longest = max([base.longest, *map(len, cut)])
        return ix

    def resolve(self, needle: str) -> tuple[str, str, str]:
        """needle -> (real value, kind, form)"""
        value = self._canonical(needle)
        return value, self.kind_of(value), "plain" if needle == value else "encoded"


def seeded_index(known) -> _Index:
    """The guard index for a set of known values, cached on it. The re-seeder builds
    it before swapping a new set in, so no request pays for the rebuild."""
    cached = getattr(known, "_guard_index", None)
    if cached is None or cached[0] != len(known):
        base, new = known._base_guard, known._new_values
        if base is not None and len(new) < max(1000, len(known) // 10):
            ix = _Index.grown(base[1], known, list(new))  # a re-seed added a few values
        else:
            ix = _Index(known=known)
        cached = (len(known), ix)
        known._guard_index, known._base_guard, known._new_values = cached, None, []
    return cached[1]


class Guard:
    def __init__(self, veil: Veil):
        self.veil = veil
        self._seeded: _Index | None = None   # big, rebuilt only when seeding changes
        self._found: _Index | None = None    # small: pattern-found values, rebuilt per new token
        self._found_key = None

    def _build(self) -> list[_Index]:
        # Strong sources only: seeded values, and values that patterns detect anywhere.
        # NER guesses are redacted where they occur but never become global needles
        # (a mis-tagged "Claude Code" would otherwise be rewritten in system prompts).
        known = self.veil.known._entries
        self._seeded = seeded_index(self.veil.known)
        if self._found_key != (len(known), self.veil.vault.version):
            self._found = _Index({value: kind for (kind, value) in self.veil.vault._by_value
                                  if kind in PATTERN_KINDS and value not in known})
            self._found_key = (len(known), self.veil.vault.version)
        return [self._seeded, self._found]

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
                        value = ix.norm_values[mode].get(n)
                        if value is None:
                            continue  # the other view's needle
                        kind = ix.kind_of(value)
                        if value in s:
                            continue  # verbatim: the plain pass below repairs it in place
                        findings.append(Finding(path, kind, "transformed", "[withheld]",
                                                repaired=not frozen, allowed=frozen))
                        return s if frozen else WITHHELD
        for view in views(s):
            for ix in indexes:
                hidden = [n for _, _, n in ix.plain.find(view) if n not in s]
                if hidden:
                    value, kind, _ = ix.resolve(hidden[0])
                    findings.append(Finding(path, kind, "escaped", "[withheld]", repaired=not frozen, allowed=frozen))
                    return s if frozen else WITHHELD
        hits: list[tuple[int, int, str, str, str]] = []  # start, end, replacement, kind, form
        for ix in indexes:
            for start, end, needle in ix.plain.find(s):
                value, kind, form = ix.resolve(needle)
                hits.append((start, end, self._token(value, kind), kind, form))
        runs = b64_runs(s) if len(s) >= 12 else []
        if runs:  # one matcher pass over every run's decodings
            starts, decoded, at = [], [], 0
            for a, b, text in runs:
                starts.append(at)
                decoded.append(text)
                at += len(text) + 1
            joined = "\n".join(decoded)
            for ix in indexes:
                for x, y, needle in ix.plain.find(joined):
                    a, b, _ = runs[bisect.bisect_right(starts, x) - 1]
                    if y - x >= 6 and not any(p < b and a < q for p, q, *_ in hits):
                        value, kind, _ = ix.resolve(needle)
                        hits.append((a, b, "[veil:base64-redacted]", kind, "base64"))
        if content and not frozen and ("\n" in s or "\ufffd" in s):
            pattern = self.veil.token_pattern()
            tokens = [(m.start(), m.end()) for m in pattern.finditer(s)] if pattern else []
            # U+FFFD: a byte-wise cut (GNU `cut -b`, head -c) split a UTF-8 character
            ends = [i for i, c in enumerate(s) if c in "\r\n\ufffd"] + [len(s)]
            starts = [0] + [i + 1 for i, c in enumerate(s) if c in "\n\ufffd"]
            word = lambda c: c.isalnum() or c == "_"
            free = lambda a, b: not any(x < b and a < y for x, y in tokens) and \
                not any(x < b and a < y for x, y, *_ in hits)
            rs = s[::-1]
            for ix in indexes:
                if not ix.longest:
                    continue
                candidates = []
                for a in set(ix.plain.anchors(s)):  # head: from a value's start to a line end
                    if a == 0 or not word(s[a - 1]):
                        b = ends[bisect.bisect_left(ends, a)]
                        candidates.append((a, b, ix.heads))
                for r in set(ix.tail_anchors.anchors(rs)):  # tail: from a line start to a value's end
                    b = len(s) - r
                    if b == len(s) or not word(s[b]):
                        a = starts[bisect.bisect_right(starts, b - 6) - 1]
                        candidates.append((a, b, ix.tails))
                for a, b, table in sorted(candidates):
                    if not 6 <= b - a < ix.longest:
                        continue
                    value = table.owner(s[a:b])
                    # never inside veil's own tokens ("Ab12 Example Street" vs a surname "Streeting")
                    if value and value not in s and free(a, b):
                        hits.append((a, b, PARTIAL, ix.kind_of(value), "partial"))
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
