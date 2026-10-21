"""Shell-injection fuzzer: random nestings of shell and interpreter contexts (quotes,
$( ), backticks, heredocs, bash -c, eval, python/node/perl/ruby code, pipes into
interpreters, variables flowing into code) around hostile values. Every generated
command is rehydrated by veil and *executed*; a file created by a value means data
became code.

    uv run python -m veil_dev.shellfuzz --cases 10000 --seed 1
"""

from __future__ import annotations

import argparse
import glob
import os
import random
import subprocess
import sys
import tempfile

from veil.anthropic import Policy, rehydrate_tool_input
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault

HOSTILE = [
    "O'Brien", 'say "hi"', "x\\", "$(touch PWNED_dollar)", "`touch PWNED_backtick`",
    "x'; touch PWNED_sq; echo '", 'x"; touch PWNED_dq; echo "',
    "{__import__('os').system('touch PWNED_fstring')}", "${require('child_process').execSync('touch PWNED_tpl')}",
    "#{`touch PWNED_ruby`}", "@{[ `touch PWNED_perl` ]}", "\\(input)",
    "x')\nimport os; os.system('touch PWNED_nl')\nprint('", "a\nEOF\ntouch PWNED_eof",
    "';$(touch PWNED_a);'", '";`touch PWNED_b`;"', "\\'$(touch PWNED_c)", "\\\"$(touch PWNED_d)\\\"",
    "'\"$(touch PWNED_e)\"'", "touch PWNED_plain", "a;touch PWNED_semi", "x|touch PWNED_pipe",
]

WRAPPERS = [
    lambda x: f"'{x}'", lambda x: f'"{x}"', lambda x: x, lambda x: f"$'{x}'",
    lambda x: f'"$(printf %s {x})"', lambda x: f"$(printf %s {x})", lambda x: f'"`printf %s {x}`"',
    lambda x: f"bash -c {x}", lambda x: f"sh -c {x}", lambda x: f"eval {x}",
    lambda x: f"python3 -c {x}", lambda x: f"node -e {x}", lambda x: f"perl -e {x}", lambda x: f"ruby -e {x}",
    lambda x: f"cat <<EOF\n{x}\nEOF", lambda x: f"cat <<'EOF'\n{x}\nEOF", lambda x: f"python3 <<EOF\n{x}\nEOF",
    lambda x: f"print('{x}')", lambda x: f'print("{x}")', lambda x: f"print(f'{x}')", lambda x: f"echo {x}",
    lambda x: f"printf %s {x}", lambda x: f"sqlite3 :memory: {x}", lambda x: f"select '{x}'",
    lambda x: f"echo {x} | sh", lambda x: f"printf %s {x} | bash", lambda x: f'v={x}; eval "$v"',
    lambda x: f'v={x}; python3 -c "print($v)"', lambda x: f"echo {x} | xargs -I{{}} sh -c 'echo {{}}'",
    lambda x: f'echo "select {x}" | sqlite3 :memory:', lambda x: f"cat <<EOF | sh\n{x}\nEOF",
    lambda x: f"echo {x} | python3", lambda x: f'v={x}; sh -c "$v"', lambda x: f"echo {x} | xargs sh -c",
    lambda x: f"{x} | sh", lambda x: f"printf '%s\\n' {x} | while read l; do eval \"$l\"; done",
]


def run(cases: int, seed: int, workdir: str | None = None) -> list[tuple[str, str, str]]:
    """Returns (value, command with token, command as executed) for every execution."""
    known = KnownValues(min_len=1)
    for i, v in enumerate(HOSTILE):
        known.add(v, "name", f"u:{i}")
    veil = Veil(Vault(":memory:", b"fuzz"), known)
    rng = random.Random(seed)
    work = workdir or tempfile.mkdtemp(prefix="veil-shellfuzz-")
    bad = []
    for _ in range(cases):
        value = rng.choice(HOSTILE)
        cmd = veil.redact(value)
        for _ in range(rng.randint(1, 4)):
            cmd = rng.choice(WRAPPERS)(cmd)
        ran = rehydrate_tool_input(veil, Policy(), "Bash", {"command": cmd})["command"]
        for f in glob.glob(os.path.join(work, "*")):
            os.remove(f)
        try:
            subprocess.run(["bash", "-c", ran], cwd=work, capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass
        if glob.glob(os.path.join(work, "PWNED*")):
            bad.append((value, cmd, ran))
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="veil_dev.shellfuzz")
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)
    bad = run(args.cases, args.seed)
    print(f"{args.cases} commands executed, {len(bad)} code executions")
    for value, cmd, ran in bad[:10]:
        print(f"  value {value!r}\n    model wrote: {cmd!r}\n    ran:         {ran!r}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
