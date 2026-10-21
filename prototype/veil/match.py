"""Multi-string matching with Aho-Corasick.

A regex alternation of thousands of literals is O(text x needles) in Python's
backtracking `re`; Aho-Corasick finds every needle in one pass. Matches are
filtered by identifier boundaries (so `alice_w` never matches inside
`malice_wrapper`) and reduced to leftmost-longest, non-overlapping hits --
the same semantics the regex version had.
"""

from __future__ import annotations

import ahocorasick


def _is_word(ch: str) -> bool:
    return ch == "_" or (ch.isascii() and ch.isalnum())


class Matcher:
    def __init__(self, needles, bounded: bool = True):
        self.bounded = bounded
        self._auto = ahocorasick.Automaton()
        for n in needles:
            if n:
                self._auto.add_word(n, n)
        self._empty = len(self._auto) == 0
        if not self._empty:
            self._auto.make_automaton()

    def find(self, text: str) -> list[tuple[int, int, str]]:
        """Leftmost-longest non-overlapping (start, end, needle)."""
        if self._empty or not text:
            return []
        hits = []
        for last, needle in self._auto.iter(text):
            start, end = last - len(needle) + 1, last + 1
            if self.bounded and ((start > 0 and _is_word(text[start - 1])) or
                                 (end < len(text) and _is_word(text[end]))):
                continue
            hits.append((start, end, needle))
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        out, pos = [], 0
        for h in hits:
            if h[0] >= pos:
                out.append(h)
                pos = h[1]
        return out
