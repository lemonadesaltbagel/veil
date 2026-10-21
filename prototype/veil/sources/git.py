"""Seed the people in a repository's history: authors, committers and Co-authored-by
trailers (names and emails, one person per email). Bots and service identities are
skipped: `[bot]` names, GitHub/GitLab noreply bot addresses, and AI co-authors such as
`Claude <noreply@anthropic.com>` (seeding "Claude" would rewrite "Claude Code").

    veil seed git:.            (veil init adds it automatically when the project is a repo)
"""

from __future__ import annotations

import re
import subprocess

from ..detect import KnownValues
from .core import Field, Report

SEP = "\x1f"
TRAILER = re.compile(r"^co-authored-by:\s*(.+?)\s*<([^>]+)>\s*$", re.I | re.M)
# Humans' GitHub noreply addresses (123+name@users.noreply.github.com) identify them and are
# seeded; bots carry [bot] or a no-reply/service local part.
BOT_EMAIL = re.compile(r"\[bot\]|^no-?reply@|^actions?@github\.com$|^(bot|ci|build)@", re.I)
BOT_NAME = re.compile(r"\[bot\]$|^(github|gitlab)[ -]?(actions|ci)?$|^dependabot|^renovate|^copilot|^claude$|^codex$", re.I)


def is_bot(name: str, email: str) -> bool:
    return bool(BOT_EMAIL.search(email.strip()) or BOT_NAME.search(name.strip()))


def people(repo: str, max_commits: int = 200_000) -> dict[str, set[str]]:
    """email (lower-case) -> names used with it."""
    fmt = SEP.join(["%an", "%ae", "%cn", "%ce", "%(trailers:key=Co-authored-by,valueonly=false)"]) + "\x1e"
    r = subprocess.run(["git", "-C", repo, "log", "--all", f"-n{max_commits}", f"--format={fmt}"],
                       capture_output=True, encoding="utf-8", errors="replace", timeout=120)  # not the locale (cp1252)
    if r.returncode != 0:
        raise ValueError(f"not a git repository: {repo}")
    out: dict[str, set[str]] = {}
    for rec in r.stdout.split("\x1e"):
        parts = rec.strip("\n").split(SEP)
        if len(parts) < 5:
            continue
        pairs = [(parts[0], parts[1]), (parts[2], parts[3])] + TRAILER.findall(parts[4])
        for name, email in pairs:
            name, email = name.strip(), email.strip()
            if email and not is_bot(name, email):
                out.setdefault(email.lower(), set()).add(name)
    return out


def seed_git(known: KnownValues, repo: str) -> Report:
    report, before = Report(), len(known)
    fields = {"email": Field("git", "author.email", "email", "git"), "name": Field("git", "author.name", "name", "git"),
              "username": Field("git", "author.name", "username", "git")}
    for email, names in sorted(people(repo).items()):
        group = f"git:{email}"
        n = len(known)
        known.add(email, "email", group)
        fields["email"].values += len(known) - n
        for name in sorted(names):
            if not name or name.lower() == email.split("@")[0].lower():
                continue
            kind = "name" if len(name.split()) >= 2 else "username"  # a one-word name is a handle
            n = len(known)
            known.add(name, kind, group)
            fields[kind].values += len(known) - n
    report.fields = [f for f in fields.values() if f.values]
    report.added = len(known) - before
    return report
