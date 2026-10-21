"""Multi-string matching with Aho-Corasick over short anchors.

A regex alternation of thousands of literals is O(text x needles) in Python's
backtracking `re`; Aho-Corasick finds every needle in one pass. Matches are
filtered by identifier boundaries (so `alice_w` never matches inside
`malice_wrapper`) and reduced to leftmost-longest, non-overlapping hits --
the same semantics the regex version had.

Memory: an automaton node costs ~100 bytes in pyahocorasick, so a trie of a
million full needles costs gigabytes. Only each needle's first ANCHOR characters
go into the automaton; an anchor hit is confirmed by looking up text slices of
the needle lengths that share that anchor (a bitmask) in a set. The lookups are
cheap because anchors of real values rarely occur in ordinary text.
"""

from __future__ import annotations

import bisect

import ahocorasick

ANCHOR = 6


def _is_word(ch: str) -> bool:
    return ch == "_" or (ch.isascii() and ch.isalnum())


class Matcher:
    def __init__(self, needles=(), bounded: bool = True):
        self.bounded = bounded
        self._set: set[str] = set()
        self._masks: dict[str, int] = {}  # anchor -> bitmask of needle lengths
        self._auto = ahocorasick.Automaton()
        self._stale = False
        for n in needles:
            self.add(n)
        self._build()

    def add(self, n: str) -> None:
        """Add a needle. Cheap when its anchor is already known (most tokens:
        `First_…`, `user_x…`); a new anchor rebuilds the automaton on next use."""
        if not n or n in self._set:
            return
        self._set.add(n)
        a = n[:ANCHOR]
        if a not in self._masks:
            self._masks[a] = 0
            self._auto.add_word(a, a)
            self._stale = True
        self._masks[a] |= 1 << len(n)

    def extended(self, needles) -> "Matcher":
        """Grow while other threads may be matching: lengths and the needle set are
        updated in place (harmless to a concurrent find); a new anchor gets a new
        automaton (over anchors only, so cheap), returned for the caller to swap in."""
        fresh = False
        for n in needles:
            if n and n not in self._set:
                a = n[:ANCHOR]
                if a not in self._masks:
                    self._masks[a] = 0
                    fresh = True
                self._masks[a] |= 1 << len(n)
                self._set.add(n)
        if not fresh:
            return self
        m = Matcher.__new__(Matcher)
        m.bounded, m._set, m._masks, m._stale = self.bounded, self._set, self._masks, False
        m._auto = ahocorasick.Automaton()
        for a in list(self._masks):
            m._auto.add_word(a, a)
        m._auto.make_automaton()
        return m

    def _build(self) -> None:
        if self._stale:
            self._auto.make_automaton()
            self._stale = False

    def __len__(self) -> int:
        return len(self._set)

    def __contains__(self, s: str) -> bool:
        return s in self._set

    def anchors(self, text: str):
        """Start offsets of every anchor occurrence (candidate needle starts)."""
        if not self._masks or not text:
            return
        self._build()
        for last, a in self._auto.iter(text):
            yield last - len(a) + 1

    def find(self, text: str) -> list[tuple[int, int, str]]:
        """Leftmost-longest non-overlapping (start, end, needle)."""
        if not self._masks or not text:
            return []
        self._build()
        hits, size, needles, bounded, masks = [], len(text), self._set, self.bounded, self._masks
        for last, a in self._auto.iter(text):
            alen = len(a)
            start = last - alen + 1
            if bounded and start > 0 and _is_word(text[start - 1]):
                continue
            mask = masks[a]
            while mask:  # longest first; the first length that matches wins for this start
                length = mask.bit_length() - 1
                mask ^= 1 << length
                end = start + length
                if end > size:
                    continue
                if bounded and end < size and _is_word(text[end]):
                    continue
                if length == alen or text[start:end] in needles:
                    hits.append((start, end, text[start:end]))
                    break
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        out, pos = [], 0
        for h in hits:
            if h[0] >= pos:
                out.append(h)
                pos = h[1]
        return out


class Prefixes:
    """Is a string a proper prefix (or, with reverse=True, suffix) of one of the values?
    A sorted list and bisect: no per-prefix strings are stored."""

    def __init__(self, values, reverse: bool = False):
        self.reverse = reverse
        self._sorted = sorted({v[::-1] if reverse else v for v in values})

    def __len__(self) -> int:
        return len(self._sorted)

    def owner(self, part: str) -> str | None:
        key = part[::-1] if self.reverse else part
        i = bisect.bisect_right(self._sorted, key)  # skip an exact match: proper prefixes only
        if i < len(self._sorted) and self._sorted[i].startswith(key):
            return self._sorted[i][::-1] if self.reverse else self._sorted[i]
        return None
