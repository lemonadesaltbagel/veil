"""Values restored into files fit the file's language where they land (and still only
values that already exist in that file). Each case is checked by parsing or running
the resulting file."""

import ast
import csv
import io
import json
import subprocess

import pytest

from veil.anthropic import Policy, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.responses import _patch_input
from veil.vault import Vault

VALUES = ["O'Brien", 'Say "hi"', "back\\slash", "{__import__('os').system('touch PWNED')}", "Zoë, Ørsted"]


@pytest.fixture
def veil():
    known = KnownValues(min_len=1)
    for i, v in enumerate(VALUES):
        known.add(v, "name", f"p:{i}")
    return Veil(Vault(":memory:", b"f"), known)


def _edit(veil, path, old, new):
    return rehydrate_tool_input(veil, Policy(), "Edit", {"file_path": str(path), "old_string": old, "new_string": new})


@pytest.mark.parametrize("value", VALUES)
def test_python_literals_comments_and_fstrings(veil, tmp_path, value):
    f = tmp_path / "people.py"
    f.write_text(f"OWNER = {value!r}\n# TODO\nx = 1\n", encoding="utf-8")  # the value exists (escaped) in the file
    tok = veil.redact(value)
    out = _edit(veil, f, "# TODO\nx = 1\n", f"# TODO\nA = '{tok}'\nB = \"{tok}\"\nC = f'{{x}} {tok}'\n# by {tok}\nx = 1\n")
    new = f.read_text(encoding="utf-8").replace("# TODO\nx = 1\n", out["new_string"])
    tree = ast.parse(new)                                            # still valid Python
    ns = {"x": 1}
    exec(compile(tree, "people.py", "exec"), ns)
    assert ns["A"] == ns["B"] == value and ns["C"] == f"1 {value}"  # same value, not code
    assert f"# by {value}" in new or tok in new                     # comment: as is (no newline)


def test_code_position_keeps_the_token(veil, tmp_path):
    f = tmp_path / "a.py"
    f.write_text("OWNER = \"O'Brien\"\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    assert _edit(veil, f, 'OWNER = "O\'Brien"\n', f"OWNER = {tok}\n")["new_string"] == f"OWNER = {tok}\n"


@pytest.mark.parametrize("value", VALUES)
def test_json_yaml_csv_stay_parseable(veil, tmp_path, value):
    tok = veil.redact(value)
    j = tmp_path / "users.json"
    j.write_text(json.dumps([{"name": value}], ensure_ascii=False), encoding="utf-8")
    out = rehydrate_tool_input(veil, Policy(), "Write", {"file_path": str(j), "content": f'[{{"name": "{tok}"}}, {{"by": "{tok}"}}]'})
    assert json.loads(out["content"]) == [{"name": value}, {"by": value}]
    c = tmp_path / "users.csv"
    c.write_text(f'id,name\n1,"{value.replace(chr(34), chr(34) * 2)}"\n', encoding="utf-8")
    out = rehydrate_tool_input(veil, Policy(), "Write", {"file_path": str(c), "content": f'id,name\n1,{tok}\n2,"{tok}"\n'})
    assert [r["name"] for r in csv.DictReader(io.StringIO(out["content"]))] == [value, value]
    pytest.importorskip("yaml")
    import yaml
    y = tmp_path / "users.yaml"
    y.write_text(yaml.safe_dump({"owner": value}, allow_unicode=True), encoding="utf-8")
    out = rehydrate_tool_input(veil, Policy(), "Write", {"file_path": str(y),
                               "content": f"a: {tok}\nb: \"{tok}\"\nc: '{tok}'\n"})
    assert yaml.safe_load(out["content"]) == {"a": value, "b": value, "c": value}


def test_new_values_still_never_enter_a_file(veil, tmp_path):
    f = tmp_path / "x.py"
    f.write_text("x = 1\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    out = rehydrate_tool_input(veil, Policy(), "Write", {"file_path": str(f), "content": f"OWNER = '{tok}'\n"})
    assert out["content"] == f"OWNER = '{tok}'\n"


def test_multiedit_applies_in_order(veil, tmp_path):
    f = tmp_path / "m.js"
    f.write_text("const a = 'O\\'Brien';\nconst b = 1;\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    out = rehydrate_tool_input(veil, Policy(), "MultiEdit", {"file_path": str(f), "edits": [
        {"old_string": "const b = 1;", "new_string": f"const b = `${{a}} {tok}`;"},
        {"old_string": "const a", "new_string": "let a"}]})
    assert out["edits"][0]["new_string"] == "const b = `${a} O'Brien`;"   # template literal: ' needs no escape
    assert out["edits"][1] == {"old_string": "const a", "new_string": "let a"}


def test_shell_script_uses_command_escaping(veil, tmp_path):
    f = tmp_path / "run.sh"
    f.write_text("#!/bin/sh\n# owner: O'Brien\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    out = _edit(veil, f, "# owner: O'Brien\n", f"# owner: O'Brien\nprintf '%s' '{tok}'\n")
    script = f.read_text(encoding="utf-8").replace("# owner: O'Brien\n", out["new_string"])
    assert subprocess.run(["sh", "-c", script], capture_output=True, text=True).stdout == "O'Brien"


def test_apply_patch_added_lines_fit_the_file(veil, tmp_path):
    f = tmp_path / "people.py"
    f.write_text("OWNER = \"O'Brien\"\n", encoding="utf-8")
    tok = veil.redact("O'Brien")
    patch = (f"*** Begin Patch\n*** Update File: {f}\n@@\n OWNER = \"O'Brien\"\n+COPY = '{tok}'\n*** End Patch")
    out = _patch_input(veil, Policy(), patch)
    added = [l[1:] for l in out.splitlines() if l.startswith("+")]
    assert added == ["COPY = 'O\\'Brien'"] and ast.literal_eval(added[0].split(" = ")[1]) == "O'Brien"
