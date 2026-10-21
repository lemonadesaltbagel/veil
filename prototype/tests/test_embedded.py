"""Real values restored into code for a *second* language (python -c, node -e, heredocs,
bash -c, jq, awk, SQL...) must stay data in every layer. Each case really runs: the
command must print the exact value, or keep the pseudonym (when the value can't be
represented safely there) -- and must never execute anything."""

import shutil
import subprocess

import pytest

from veil.anthropic import Policy, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault

HOSTILE = [
    "O'Brien",
    'say "hi"',
    "x\\",                                                   # trailing backslash eats a closing quote
    "$(touch PWNED_dollar)",
    "`touch PWNED_backtick`",
    "x'; touch PWNED_sq; echo '",
    'x"; touch PWNED_dq; echo "',
    "{__import__('os').system('touch PWNED_fstring')}",      # Python f-string
    "${require('child_process').execSync('touch PWNED_tpl')}",  # JS template literal
    "#{`touch PWNED_ruby`}",                                  # Ruby interpolation
    "@{[ `touch PWNED_perl` ]}",                               # Perl interpolation
    "\\(input)",                                              # jq interpolation
    "x')\nimport os; os.system('touch PWNED_nl')\nprint('",   # newline: ends heredocs, lines
    "a\nEOF\ntouch PWNED_eof",                                # would end the heredoc early
    "Zoë Ørsted 日本",
]

# (template, interpreter needed, output suffix the template adds)
CASES = [
    ("cat <<EOF\n{t}\nEOF", "cat", "\n"),
    ("cat <<'EOF'\n{t}\nEOF", "cat", "\n"),
    ("cat <<-\"EOF\"\n\t{t}\n\tEOF", "cat", "\n"),
    ("python3 -c \"import sys; sys.stdout.write('{t}')\"", "python3", ""),
    ("python3 -c 'import sys; sys.stdout.write(\"{t}\")'", "python3", ""),
    ("python3 -c \"import sys; sys.stdout.write(f'{t}')\"", "python3", ""),
    ("python3 -c \"import sys; sys.stdout.write(r'{t}')\"", "python3", ""),
    ("python3 - <<'EOF'\nimport sys; sys.stdout.write('''{t}''')\nEOF", "python3", ""),
    ("python3 <<EOF\nimport sys; sys.stdout.write(\"{t}\")\nEOF", "python3", ""),
    ("uv run --no-project python3 -c \"import sys; sys.stdout.write('{t}')\"", "uv", ""),
    ("node -e \"process.stdout.write('{t}')\"", "node", ""),
    ("node -e 'process.stdout.write(`{t}`)'", "node", ""),
    ("node <<'EOF'\nprocess.stdout.write(\"{t}\")\nEOF", "node", ""),
    ("ruby -e 'print \"{t}\"'", "ruby", ""),
    ("ruby -e \"print '{t}'\"", "ruby", ""),
    ("perl -e 'print \"{t}\"'", "perl", ""),
    ("perl -e \"print '{t}'\"", "perl", ""),
    ("php -r 'echo \"{t}\";'", "php", ""),
    ("jq -jn '\"{t}\"'", "jq", ""),
    ("awk 'BEGIN{{printf \"%s\", \"{t}\"}}'", "awk", ""),
    ("bash -c \"printf %s '{t}'\"", "bash", ""),
    ("bash -c 'printf %s \"{t}\"'", "bash", ""),
    ("sh -c \"printf %s {t}\"", "sh", ""),
    ("bash -lc \"python3 -c \\\"import sys; sys.stdout.write('{t}')\\\"\"", "python3", ""),
    ("printf %s \"$(printf %s '{t}')\"", "bash", ""),
    ("printf %s \"`printf %s '{t}'`\"", "bash", ""),
    ("printf %s $'{t}'", "bash", ""),
    ("eval \"printf %s '{t}'\"", "bash", ""),
    ("sqlite3 :memory: \"select '{t}'\"", "sqlite3", "\n"),
    ("sqlite3 :memory: <<'EOF'\nselect '{t}';\nEOF", "sqlite3", "\n"),
]


@pytest.fixture(scope="module")
def veil():
    known = KnownValues(min_len=1)
    for i, v in enumerate(HOSTILE):
        known.add(v, "name", f"u:{i}")
    return Veil(Vault(":memory:", b"e"), known)


@pytest.mark.parametrize("template,needs,suffix", CASES, ids=[c[0].split("\n")[0][:40] for c in CASES])
def test_embedded_contexts(veil, tmp_path, template, needs, suffix):
    if not shutil.which(needs):
        pytest.skip(f"{needs} not installed")
    kept = 0
    for value in HOSTILE:
        tok = veil.redact(value)
        cmd = rehydrate_tool_input(veil, Policy(), "Bash", {"command": template.format(t=tok)})["command"]
        r = subprocess.run(["bash", "-c", cmd], cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert not list(tmp_path.glob("PWNED*")), f"code execution via {value!r}:\n{cmd}"
        if tok in cmd:  # left as a pseudonym: could not be represented safely
            kept += 1
            continue
        if value.endswith("\\") and "<<EOF" in template:
            continue
        assert r.stdout == value + suffix, (value, cmd, r.stdout, r.stderr)
    if "r'" not in template and "`printf" not in template:  # raw strings / backticks: few values fit
        assert kept <= len(HOSTILE) // 2, f"{kept} values left as pseudonyms: too conservative"


def test_fuzzed_nestings_never_execute(tmp_path):
    from veil_dev.shellfuzz import run
    bad = run(cases=300, seed=7, workdir=str(tmp_path))  # `python -m veil_dev.shellfuzz` for more
    assert bad == [], bad[:3]
