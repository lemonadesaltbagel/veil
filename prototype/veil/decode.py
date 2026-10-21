"""Alternative readings of a string in which a real value may hide.

An agent with a shell can transform data before veil sees it. Found with a
real model: `sed -n l app.log` prints non-ASCII as octal (`Stra\\303\\237e`) and
wraps long lines with a trailing backslash, so `leonekoh\\<newline>ler@...`
matched nothing -- the model then decoded it in its reasoning.

`views()` undoes the common, cheap transforms: line continuations, sed `l`
end-of-line `$`, octal / `\\xNN` / `\\uNNNN` escapes. (base64 is handled by the
guard's base64 needles; hex dumps are blocked at the command level.)
"""

from __future__ import annotations

import re

_CONT = re.compile(r"\\\r?\n")                 # backslash-newline line continuation
_SED_EOL = re.compile(r"\$(?=\r?\n|$)")         # sed `l` marks line ends with $
_ESC = re.compile(r"(?:\\[0-7]{3}|\\x[0-9a-fA-F]{2})+")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")


def _bytes_escapes(m: re.Match) -> str:
    raw = bytearray()
    for part in re.findall(r"\\([0-7]{3})|\\x([0-9a-fA-F]{2})", m.group()):
        raw.append(int(part[0], 8) if part[0] else int(part[1], 16))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def views(text: str) -> list[str]:
    """Decoded variants of `text` that differ from it (empty if nothing to undo)."""
    if "\\" not in text:
        return []
    joined = _SED_EOL.sub("", _CONT.sub("", text))
    decoded = _UESC.sub(lambda m: chr(int(m.group(1), 16)), _ESC.sub(_bytes_escapes, joined))
    return [v for v in dict.fromkeys([joined, decoded]) if v != text]


# -- transforms an agent can apply with one shell command --------------------
import codecs
from urllib.parse import unquote

_HEXRUN = re.compile(r"\b(?:[0-9A-Fa-f]{2}){6,}\b")
_CODES = re.compile(r"(?:\b\d{2,6}\b[\s|,;]+){3,}\b\d{2,6}\b")


def _hex(text: str) -> str:
    def dec(m):
        try:
            return bytes.fromhex(m.group()).decode("utf-8")
        except ValueError:
            return m.group()
    return _HEXRUN.sub(dec, text)


def _codes(text: str) -> str:
    def dec(m):
        try:
            return "".join(chr(int(n)) for n in re.findall(r"\d+", m.group()))
        except (ValueError, OverflowError):
            return m.group()
    return _CODES.sub(dec, text)


def norm(text: str) -> str:
    """Case- and whitespace-insensitive form (also the form needles are compared in)."""
    return re.sub(r"\s+", "", text).casefold()


def strong_views(text: str) -> list[str]:
    """Normalised views undoing cheap one-command transforms: case changes, spacing /
    one-char-per-line, reversal, rot13, hex runs (sql hex(), xxd -p), URL encoding.
    Compare against norm()'d needles of >= 8 chars only (short values collide)."""
    base = [text] + views(text)
    out = set()
    for t in base:
        for v in (t, unquote(t), _hex(t)):
            n = norm(v)
            out |= {n, n[::-1], codecs.encode(n, "rot13")}
            # rev reverses each line, not the whole text
            out.add(norm("\n".join(line[::-1] for line in v.splitlines())))
    return list(out)


def deep_views(text: str) -> list[str]:
    """Oracle for audits/red-team: strong views plus character-code sequences."""
    return strong_views(text) + [norm(_codes(text))]
