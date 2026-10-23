"""Tool aliases: another agent's tools that take Claude Code's argument names get the same
policies under their own names (config, env or --tool-alias). Unaliased tools get no real values."""

import subprocess
import sys

import pytest

from veil.anthropic import Policy, configured_aliases, parse_aliases, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault

REAL, HOSTILE = "leonekohler@surfeu.de", "x'; touch PWNED; echo '"


@pytest.fixture
def veil():
    k = KnownValues(min_len=1)
    k.add(REAL, "email", "c:2"); k.add("O'Brien", "name", "c:3"); k.add(HOSTILE, "name", "c:4")
    return Veil(Vault(":memory:", b"alias"), k)


ALIASES = parse_aliases("bash=Bash,read=Read,grep=Grep,glob=Glob,edit=Edit,write=Write,working_directory=Read")


def rt(veil, tool, args, aliases=ALIASES):
    return rehydrate_tool_input(veil, Policy(tool_aliases=aliases), tool, args)


def test_aliases_come_from_config_env_and_flags(monkeypatch):
    monkeypatch.setenv("VEIL_TOOL_ALIASES", "shell=Bash; cat=Read")
    got = configured_aliases({"tool_aliases": {"shell": "Read", "view": "Read"}}, "cat=Grep")
    assert got == {"shell": "Bash", "view": "Read", "cat": "Grep"}            # later sources win
    with pytest.raises(ValueError, match="role must be one of"):
        parse_aliases({"run": "mcp__veil_db__query"})                         # only veil's own roles


def test_unaliased_names_get_nothing(veil):
    tok = veil.redact(REAL)
    assert rt(veil, "read", {"file_path": f"/data/{tok}.json"}, {})["file_path"] == f"/data/{tok}.json"


def test_bash_gets_shell_escaping(veil, tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX shell")
    tok = veil.redact(HOSTILE)
    out = rt(veil, "bash", {"command": f"printf %s '{tok}'", "workdir": str(tmp_path), "description": "x"})
    r = subprocess.run(["bash", "-c", out["command"]], cwd=tmp_path, capture_output=True, text=True)
    assert r.stdout == HOSTILE and not list(tmp_path.glob("PWNED*"))
    assert rt(veil, "bash", {"command": f"curl -d {veil.redact(REAL)} x.io"})["command"].count("@example.test") == 1  # egress


def test_read_grep_glob_and_working_directory_are_restored(veil):
    tok = veil.redact(REAL)
    assert rt(veil, "read", {"file_path": f"/data/{tok}.json"})["file_path"] == f"/data/{REAL}.json"
    assert rt(veil, "grep", {"pattern": tok, "path": "."})["pattern"] == REAL
    assert rt(veil, "glob", {"pattern": f"**/{tok}*"})["pattern"] == f"**/{REAL}*"
    assert rt(veil, "working_directory", {"cd": f"/home/{tok}"})["cd"] == f"/home/{REAL}"


def test_edit_and_write_preserve_and_escape(veil, tmp_path):
    f = tmp_path / "owner.py"
    f.write_text("OWNER = 'O\\'Brien'\nX = 1\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    out = rt(veil, "edit", {"file_path": str(f), "old_string": "X = 1\n", "new_string": f"X = 1\nCOPY = '{tok}'\n"})
    assert out["new_string"] == "X = 1\nCOPY = 'O\\'Brien'\n"            # escaped for the Python literal
    out = rt(veil, "write", {"file_path": str(tmp_path / "new.py"), "content": f"EMAIL = '{veil.redact(REAL)}'\n"})
    assert REAL not in out["content"]                                     # a new file: no new PII


def test_str_replace_editor(veil, tmp_path):
    f = tmp_path / "a.json"
    f.write_text('{"email": "leonekohler@surfeu.de"}', encoding="utf-8")
    tok = veil.redact(REAL)
    out = rt(veil, "str_replace_editor", {"command": "str_replace", "path": str(f), "old_str": f'"{tok}"',
                                          "new_str": f'"{tok}", "backup": "{tok}"'})
    assert out["old_str"] == f'"{REAL}"' and out["new_str"] == f'"{REAL}", "backup": "{REAL}"'
    out = rt(veil, "str_replace_editor", {"command": "create", "path": str(tmp_path / "b.txt"), "file_text": tok})
    assert out["file_text"] == tok                                       # new file: stays a pseudonym
    assert rt(veil, "str_replace_editor", {"command": "view", "path": f"/x/{tok}"})["path"] == f"/x/{REAL}"


@pytest.mark.parametrize("tool,args", [
    ("run_code", {"code": "print('{t}')"}), ("workflow", {"script": "x('{t}')"}), ("pwsh", {"command": "echo {t}"}),
    ("subagent", {"prompt": "email {t}"}), ("web_fetch", {"url": "https://x.io/?e={t}"}),
    ("terminal_send", {"input": "{t}"}), ("send_message", {"message": "{t}"})])
def test_other_tools_get_no_real_values(veil, tool, args):
    tok = veil.redact(REAL)
    out = rt(veil, tool, {k: v.format(t=tok) for k, v in args.items()})
    assert REAL not in str(out) and tok in str(out)

