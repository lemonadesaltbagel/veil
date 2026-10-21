"""Restoring real values into files (Edit, MultiEdit, Write, NotebookEdit, apply_patch).

The preserve policy already allows only values that exist in the target file. This
module makes the restored value *fit where it lands*, by the file's language, at the
token's position in the resulting file:

  string literal   escaped for that literal (Python f/r/b strings, JS template
                   literals, Ruby/Perl/PHP interpolation, SQL quote doubling, JSON)
  comment          the value as is, unless it contains a newline (or `*/`)
  code position    only inert values (letters, digits, _.@+-); otherwise the token stays
  shell scripts    the same layer-by-layer escaping as Bash commands
  YAML / CSV       quoting rules of the scalar or field

"Already in the file" also accepts the value's escaped spellings (`O\\'Brien` in a
Python string is O'Brien). Files of unknown type get the value as is, as before.
"""

from __future__ import annotations

import json
import os
import re

from .shell import SAFE_CODE, Escaper, escape_literal, literal_contexts

LANG_BY_EXT = {".py": "python", ".pyi": "python", ".ipynb": "python",
               ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".jsx": "js",
               ".rb": "ruby", ".php": "php", ".pl": "perl", ".pm": "perl", ".sql": "sql",
               ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".csv": "csv",
               ".sh": "sh", ".bash": "sh", ".zsh": "sh"}
YAML_PLAIN_UNSAFE = re.compile(r"^[-?:,\[\]{}#&*!|>'\"%@`\s]|: |\s#|[\n\r]|\s$")


def language(path: str) -> str | None:
    return LANG_BY_EXT.get(os.path.splitext(path or "")[1].lower())


def spellings(value: str, lang: str | None) -> set[str]:
    """How the value can appear in a file of this language."""
    out = {value}
    if lang in ("python", "js", "ruby", "perl", "php"):
        for q in ("'", '"'):
            v = escape_literal(value, lang, q, "")
            if v:
                out.add(v)
    elif lang in ("json", "yaml"):
        out.add(json.dumps(value, ensure_ascii=False)[1:-1])
        out.add(value.replace("'", "''"))
    elif lang == "sql":
        out.add(value.replace("'", "''"))
    elif lang == "csv":
        out.add(value.replace('"', '""'))
    return out


def present(value: str, existing: str, lang: str | None) -> bool:
    return any(s in existing for s in spellings(value, lang))


def fit(value: str, full: str, start: int, end: int, lang: str | None) -> str | None:
    """The value spelled for full[start:end] (where its token sits), or None to keep the token."""
    if lang is None:
        return value
    if lang == "sh":
        return Escaper(full).escape(start, end, value)
    if lang == "yaml":
        return _yaml(value, full, start)
    if lang == "csv":
        return _csv(value, full, start)
    ctx = literal_contexts(lang, full, comments=True)[start] if start < len(full) else None
    if ctx is None:
        return value if SAFE_CODE.fullmatch(value) else None
    if ctx[0] in ("#", "/*"):
        bad = "\n" in value or "\r" in value or (ctx[0] == "/*" and "*/" in value)
        return None if bad else value
    return escape_literal(value, lang, *ctx)


def _line_before(full: str, start: int) -> str:
    return full[full.rfind("\n", 0, start) + 1:start]


def _yaml(value: str, full: str, start: int) -> str | None:
    before = _line_before(full, start)
    if before.count('"') % 2:     # "double-quoted scalar"
        return json.dumps(value, ensure_ascii=False)[1:-1]
    if before.count("'") % 2:     # 'single-quoted scalar'
        return None if "\n" in value else value.replace("'", "''")
    if "#" in re.sub(r"(['\"]).*?\1", "", before):  # a comment
        return None if "\n" in value else value
    return value if not YAML_PLAIN_UNSAFE.search(value) else json.dumps(value, ensure_ascii=False)


def _csv(value: str, full: str, start: int) -> str | None:
    before = _line_before(full, start)
    if before.count('"') % 2:     # inside a quoted field
        return value.replace('"', '""')
    if any(c in value for c in ',"\n\r'):
        return '"' + value.replace('"', '""') + '"'
    return value


def restore_into(veil, text: str, allowed: set[str], lang: str | None, full: str | None = None,
                 offset: int = 0) -> str:
    """Rehydrate the allowed tokens of `text`, which sits at `offset` in `full` (the file
    as it will be). Tokens whose value can't be spelled safely there stay tokens."""
    pattern = veil.token_pattern()
    if pattern is None or not allowed:
        return text
    full = text if full is None else full
    out, pos = [], 0
    for m in pattern.finditer(text):
        tok = m.group()
        value = veil.vault.value_for(tok) if tok in allowed else None
        spelled = fit(value, full, offset + m.start(), offset + m.end(), lang) if value is not None else None
        if spelled is None:
            continue
        out += [text[pos:m.start()], spelled]
        pos = m.end()
    out.append(text[pos:])
    return "".join(out)
