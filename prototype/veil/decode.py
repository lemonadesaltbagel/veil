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
    """Word view: case-folded, whitespace runs collapsed to one space. Values keep their own
    spaces, so separate words are never glued together ('matches on' must not become
    '...atcheson', a seeded surname)."""
    return re.sub(r"\s+", " ", text).casefold().strip()


def norm_chars(text: str) -> str:
    """Character view: only *runs of single characters* are joined ('L e o n i e', one char per
    line from `grep -o .`); ordinary words are left alone. Compared against values with all
    whitespace removed."""
    return _SPREAD.sub(lambda m: re.sub(r"\s+", "", m.group()) + " ", text).casefold()


def squash(value: str) -> str:
    return re.sub(r"\s+", "", value).casefold()


_SPREAD = re.compile(r"(?:(?<!\S)\S(?:\s+|$)){4,}")


def strong_views(text: str) -> list[tuple[str, str]]:
    """(mode, view) pairs undoing cheap one-command transforms. mode 'w' (compare with
    norm(value)): case changes, reversal, rot13, hex runs (sql hex(), xxd -p), URL
    encoding. mode 'c' (compare with squash(value)): spaced-out letters, one char per line.
    Only for values >= 8 chars: short values collide."""
    out: set[tuple[str, str]] = set()
    for t in [text] + views(text):
        for v in (t, unquote(t), _hex(t)):
            w = norm(v)
            out |= {("w", w), ("w", w[::-1]), ("w", codecs.encode(w, "rot13")),
                    ("w", norm("\n".join(line[::-1] for line in v.splitlines()))),  # rev: per line
                    ("c", norm_chars(v))}
    return list(out)


def deep_views(text: str) -> list[tuple[str, str]]:
    """Oracle for audits/red-team: strong views plus character-code sequences."""
    return strong_views(text) + [("w", norm(_codes(text))), ("c", norm_chars(_codes(text)))]


# -- base64 (decoded instead of precomputed: a needle per value and alignment
#    cost ~3 automaton entries per seeded value) ---------------------------------
import binascii

_B64RUN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_URLSAFE = str.maketrans("-_", "+/")
WHOLE_BLOB = 4096  # longer runs are whole encoded blobs (images, files): decode from their start only


def b64_runs(text: str) -> list[tuple[int, int, str]]:
    """(start, end, decoded text) for each base64-looking run, decoded at every
    alignment (a value can sit at any byte offset of the encoded payload)."""
    out = []
    for m in _B64RUN.finditer(text):
        run = m.group().rstrip("=").translate(_URLSAFE)
        if run.isalpha() and (run.islower() or run.isupper()):
            continue  # a plain word, not data
        parts = []
        for k in ((0,) if len(run) > WHOLE_BLOB else (0, 1, 2, 3)):
            chunk = run[k:]
            chunk = chunk[:len(chunk) - len(chunk) % 4]
            try:
                parts.append(binascii.a2b_base64(chunk).decode("utf-8", "ignore"))
            except binascii.Error:
                pass
        out.append((m.start(), m.end(), "\n".join(parts)))
    return out
