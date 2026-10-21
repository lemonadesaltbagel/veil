"""Regression: every technique in the bypass matrix stays contained (blocked,
withheld, or fully redacted) under the decoding leak oracle."""

import os
import shutil

import pytest

from veil_dev.audit import CHINOOK, scenario
from veil_dev.redteam import TECHNIQUES, run_matrix

pytestmark = pytest.mark.skipif(not (os.path.exists(CHINOOK) and shutil.which("sqlite3") and shutil.which("rev")),
                                reason="needs datasets/chinook.sqlite, sqlite3, rev")


def test_bypass_matrix(tmp_path):
    veil, real_values, ws = scenario(str(tmp_path / "rt"))
    rows = run_matrix(veil, real_values, ws)
    assert len(rows) == len(TECHNIQUES)
    bad = [(r["technique"], r["outcome"], r["leaks"], r.get("partial")) for r in rows
           if r["outcome"] not in ("blocked (command policy)", "withheld (guard)", "redacted")]
    assert bad == []
