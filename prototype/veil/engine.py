"""Redact (real -> token) and rehydrate (token -> real) text and JSON."""

from __future__ import annotations

import dataclasses
import itertools
import re
import threading
from typing import Any, Iterable

from .detect import KnownValues, detect
from .match import Matcher
from .vault import Vault


# The person code inside each token shape: user_mz5z, user_mz5z+2@…, User Mz5z, First_Mz5z, Mz5z Example Street
TOKEN_CODE = re.compile(r"(?:user_|User |First_|Last_|card_|secret_)([A-Za-z2-9]{4,6})|^([A-Za-z2-9]{4,6}) Example Street")


class _Match:
    __slots__ = ("_s", "_e", "_t")

    def __init__(self, s: int, e: int, t: str):
        self._s, self._e, self._t = s, e, t

    def start(self) -> int:
        return self._s

    def end(self) -> int:
        return self._e

    def group(self, *_) -> str:
        return self._t


class TokenPattern:
    """The vault's tokens as a regex-compatible matcher (finditer/findall/sub), with
    the same boundaries as `(?<![WORD])token(?![WORD])`. A compiled alternation of
    10k+ tokens costs ~150 ms to rebuild and is slow to scan; this grows incrementally."""

    def __init__(self):
        self.matcher = Matcher(())
        self.count = 0
        self.maxlen = 0

    def grow(self, tokens) -> None:
        tokens = list(tokens)
        self.matcher = self.matcher.extended(tokens)
        self.count += len(tokens)
        self.maxlen = max([self.maxlen, *map(len, tokens)])

    def finditer(self, text: str):
        return [_Match(a, b, t) for a, b, t in self.matcher.find(text)]

    def findall(self, text: str) -> list[str]:
        return [t for _, _, t in self.matcher.find(text)]

    def sub(self, repl, text: str) -> str:
        out, pos = [], 0
        for a, b, t in self.matcher.find(text):
            out += [text[pos:a], repl(_Match(a, b, t)) if callable(repl) else repl]
            pos = b
        out.append(text[pos:])
        return "".join(out)


class Veil:
    def __init__(self, vault: Vault, known: KnownValues | None = None, ner=None):
        self.vault = vault
        self.known = known or KnownValues()
        self.ner = ner  # optional free-text detector (veil.ner.GlinerDetector)
        self.quasi_mode = "warn"  # "redact": rare quasi-identifiers are pseudonymised too (veil/quasi.py)
        self._tokens = TokenPattern()
        self._tokens_lock = threading.Lock()
        self._codes: dict[str, list[str]] = {}
        self._codes_version = -1

    # -- real -> token ---------------------------------------------------
    def redact(self, text: str, free_text: bool = False) -> str:
        """Real values -> tokens. `free_text` also runs the optional NER layer
        (messages and tool results; never system prompts or tool schemas)."""
        extra = None
        if free_text and self.ner is not None:
            pattern = self.token_pattern()
            tokens = [(m.start(), m.end()) for m in pattern.finditer(text)] if pattern else []
            codes = self.codes()
            # never let NER re-redact pieces of existing tokens ("Ayp8" in "First_Ayp8 Last_Ayp8")
            extra = [s for s in self.ner.find(text)
                     if not any(a < s.end and s.start < b for a, b in tokens) and s.value.lower() not in codes]
        if self.quasi_mode == "redact":
            # no person group: a city shared by three people must not link them to one code
            extra = (extra or []) + [dataclasses.replace(s, group=None) for s in self.known.find_quasi(text)]
        spans = detect(text, self.known, self.vault.is_token, extra)
        if not spans:
            return text
        out, pos = [], 0
        for s in spans:
            out.append(text[pos:s.start])
            out.append(self.vault.token_for(s.kind, s.value, s.group))
            pos = s.end
        out.append(text[pos:])
        return "".join(out)

    # -- token -> real ---------------------------------------------------
    def token_pattern(self) -> TokenPattern | None:
        if hasattr(self.vault, "refresh"):
            self.vault.refresh()  # tokens other processes (hooks) allocated
        if len(self.vault._by_token) < self._tokens.count:  # tokens dropped (key rotation): start over
            self._tokens = TokenPattern()
        tp = self._tokens
        if tp.count != len(self.vault._by_token):  # the vault grows in insertion order
            with self._tokens_lock:
                new = list(itertools.islice(self.vault._by_token, tp.count, None))
                if new:
                    tp.grow(new)
        return tp if tp.count else None

    def tokens_in(self, text: str) -> set[str]:
        pattern = self.token_pattern()
        return set(pattern.findall(text)) if pattern else set()

    def rehydrate(self, text: str, only: Iterable[str] | None = None) -> str:
        pattern = self.token_pattern()
        if pattern is None:
            return text
        allowed = set(only) if only is not None else None

        def sub(m) -> str:
            tok = m.group()
            if allowed is not None and tok not in allowed:
                return tok
            return self.vault.value_for(tok) or tok

        return pattern.sub(sub, text)

    # -- fragments ---------------------------------------------------------
    def codes(self) -> dict[str, list[str]]:
        """person code (lower-case) -> that person's real values."""
        key = (self.vault.version, len(self.known))
        if self._codes_version != key:
            by_group: dict[str, list[str]] = {}
            for value, (_, group) in self.known._entries.items():
                if group:
                    by_group.setdefault(group, []).append(value)
            out: dict[str, set[str]] = {}
            for tok, value in self.vault.tokens().items():
                m = TOKEN_CODE.match(tok)
                if m:
                    vals = out.setdefault((m.group(1) or m.group(2)).lower(), set())
                    vals.add(value)
                    vals.update(by_group.get(self.vault._group_of.get(tok) or "", []))
            self._codes = {c: sorted(v, key=len, reverse=True) for c, v in out.items()}
            self._codes_version = key
        return self._codes

    def code_tokens(self, code: str) -> list[str]:
        """The tokens that actually exist for a person code (for messages to the model)."""
        out = []
        for tok in self.vault.tokens():
            m = TOKEN_CODE.match(tok)
            if m and (m.group(1) or m.group(2)).lower() == code:
                out.append(tok)
        return sorted(out, key=len)

    def fragments(self, text: str) -> list[tuple[int, int, str]]:
        """Bare person codes used *outside* a whole token, e.g. LIKE '%mz5z%'.
        They can never match real data, so callers must not run them silently."""
        codes = self.codes()
        if not codes:
            return []
        pattern = self.token_pattern()
        whole = [(m.start(), m.end()) for m in pattern.finditer(text)] if pattern else []
        out = []
        for m in re.finditer(r"(?<![A-Za-z0-9])([A-Za-z2-9]{4,6})(?![A-Za-z0-9])", text):
            code = m.group(1).lower()
            if code in codes and not any(a <= m.start() < b for a, b in whole):
                out.append((m.start(), m.end(), code))
        return out

    # -- structured data -------------------------------------------------
    def redact_json(self, obj: Any) -> Any:
        return _walk(obj, self.redact)

    def rehydrate_json(self, obj: Any, only: Iterable[str] | None = None) -> Any:
        only = set(only) if only is not None else None
        return _walk(obj, lambda s: self.rehydrate(s, only))


def _walk(obj: Any, fn) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    if isinstance(obj, dict):
        return {fn(k): _walk(v, fn) for k, v in obj.items()}
    return obj
