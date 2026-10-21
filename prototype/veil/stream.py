"""Incremental rehydration of streamed text (shared by all API adapters).

A token may be split across deltas (`user_ab` + `12@example.test`), so up to
max-token-length characters are held back until it is safe to emit them.
Matching runs over (last emitted char + buffer) so look-behind/ahead see real
neighbours on both sides.
"""

from __future__ import annotations


class TextHold:
    def __init__(self, veil):
        self.veil = veil
        self.buf = ""
        self.ctx = ""

    def feed(self, text: str) -> str:
        self.buf += text
        return self._drain(final=False)

    def flush(self) -> str:
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        buf, ctx = self.buf, self.ctx
        pattern = self.veil.token_pattern()
        if pattern is None:
            cut, matches = len(buf), []
        else:
            maxlen = max(map(len, self.veil.vault.tokens()))
            cut = len(buf) if final else max(0, len(buf) - maxlen)
            matches = [m for m in pattern.finditer(ctx + buf) if m.end() > len(ctx)]
            for m in matches:
                s, e = m.start() - len(ctx), m.end() - len(ctx)
                if s < cut < e:
                    cut = s
        if cut <= 0:
            return ""
        out, pos = [], 0
        for m in matches:
            s, e = m.start() - len(ctx), m.end() - len(ctx)
            if e <= cut and s >= pos:
                out.append(buf[pos:s])
                out.append(self.veil.vault.value_for(m.group()) or m.group())
                pos = e
        out.append(buf[pos:cut])
        self.ctx, self.buf = buf[cut - 1], buf[cut:]
        return "".join(out)
