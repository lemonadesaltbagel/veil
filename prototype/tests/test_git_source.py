"""git history as a source: humans seeded (one person per email), bots and AI co-authors not."""

import subprocess

import pytest

from veil.adopt import detect_sources
from veil.detect import KnownValues
from veil.reseed import fingerprint
from veil.sources import seed


def _commit(repo, name, email, msg):
    (repo / "f.txt").write_text(msg)
    subprocess.run(["git", "-C", str(repo), "add", "f.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", f"user.name={name}", "-c", f"user.email={email}",
                    "commit", "-q", "-m", msg], check=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "proj"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    _commit(r, "Priya Raman", "priya.raman@gmail.com", "first")
    _commit(r, "priya", "priya.raman@gmail.com", "second (same person, a handle)")
    _commit(r, "Björn Hansen", "1234+bjornh@users.noreply.github.com", "fix\n\nCo-authored-by: Ana Lima <ana.lima@corp.example.net>\n"
            "Co-authored-by: Claude <noreply@anthropic.com>")
    _commit(r, "dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com", "bump")
    _commit(r, "GitHub Actions", "actions@github.com", "release")
    return r


def test_humans_seeded_bots_and_ai_coauthors_not(repo):
    k = KnownValues()
    seed(k, f"git:{repo}")
    assert k.group_of("Priya Raman") == k.group_of("priya.raman@gmail.com") == "git:priya.raman@gmail.com"
    assert k.group_of("Björn Hansen") == k.group_of("1234+bjornh@users.noreply.github.com")
    assert k.canonical("Ana Lima") and k.canonical("ana.lima@corp.example.net")
    assert not k.canonical("Claude") and not k.canonical("noreply@anthropic.com")
    assert not any("dependabot" in v or "GitHub Actions" in v for v in k._entries)


def test_init_detects_the_repo_and_reseed_notices_new_commits(repo):
    assert any(src == f"git:{repo}" for src, _ in detect_sources(str(repo)))
    before = fingerprint(f"git:{repo}")
    _commit(repo, "New Person", "new.person@example.org", "hello")
    assert fingerprint(f"git:{repo}") != before
