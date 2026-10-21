"""Rehydrating real values into shell commands must never turn data into code."""

import sqlite3
import subprocess
import sys

import pytest

from veil.anthropic import Policy, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="executes POSIX shell commands (bash, interpreters); covered on macOS/Linux CI")

NASTY = [
    "O'Brien",                                   # breaks SQL and single-quoted shell
    'Robert"); DROP TABLE Students;--',          # Bobby Tables
    "$(touch PWNED_dollar)",                     # command substitution
    "`touch PWNED_backtick`",
    'x"; touch PWNED_dq; echo "',
    "y'; touch PWNED_sq; echo '",
    "a b\\c\nnewline & | ; > < * ? ~ #",
]


@pytest.fixture
def veil():
    known = KnownValues(min_len=1)
    for i, v in enumerate(NASTY):
        known.add(v, "name", f"u:{i}")
    return Veil(Vault(":memory:", b"s"), known)


def run(cmd, cwd):
    return subprocess.run(["bash", "-c", cmd], cwd=cwd, capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("value", NASTY)
@pytest.mark.parametrize("template", ["printf %s {t}", "printf %s '{t}'", 'printf %s "{t}"', 'printf %s "pre {t} post"'])
def test_shell_contexts_are_inert(veil, tmp_path, value, template):
    tok = veil.redact(value)
    cmd = rehydrate_tool_input(veil, Policy(), "Bash", {"command": template.format(t=tok)})["command"]
    r = run(cmd, tmp_path)
    expected = template.replace("printf %s ", "").replace("'", "").replace('"', "").format(t=value)
    assert r.stdout == expected, (cmd, r.stdout, r.stderr)
    assert not list(tmp_path.glob("PWNED*")), f"command injection via {value!r}: {cmd}"


@pytest.mark.parametrize("value", NASTY)
def test_sql_literal_inside_double_quotes(veil, tmp_path, value):
    db = tmp_path / "app.db"
    con = sqlite3.connect(db)
    con.execute("create table users (name text)")
    con.execute("insert into users values (?)", (value,))
    con.commit()
    tok = veil.redact(value)
    cmd = f"sqlite3 app.db \"select count(*) from users where name = '{tok}'\""
    cmd = rehydrate_tool_input(veil, Policy(), "Bash", {"command": cmd})["command"]
    r = run(cmd, tmp_path)
    assert r.stdout.strip() == "1", (cmd, r.stdout, r.stderr)
    assert not list(tmp_path.glob("PWNED*"))
    assert con.execute("select count(*) from users").fetchone()[0] == 1  # table not dropped


def test_token_after_a_newline_is_whole_not_a_fragment(veil, tmp_path):
    tok = veil.redact("O'Brien")
    cmd = rehydrate_tool_input(veil, Policy(), "Bash", {"command": f"cat <<'EOF'\n{tok}\nEOF"})["command"]
    assert "veil:" not in cmd and run(cmd, tmp_path).stdout == "O'Brien\n"


def test_edit_restores_existing_value_at_line_start(veil, tmp_path):
    f = tmp_path / "people.txt"
    f.write_text("O'Brien\n")
    tok = veil.redact("O'Brien")
    out = rehydrate_tool_input(veil, Policy(), "Edit", {"file_path": str(f), "old_string": f"{tok}\n",
                                                       "new_string": f"# owner\n{tok}\n"})
    assert out["new_string"] == "# owner\nO'Brien\n"
