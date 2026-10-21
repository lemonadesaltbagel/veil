"""Mock test: what would a real LLM call receive?

Anthropic SDK agent loop -> veil proxy -> scripted fake LLM, over real sample
data (Chinook: 59 customers, 8 employees). Tools are really executed locally.
Every upstream payload is captured to captures/sdk/ with a REPORT.md and
scanned for every real value. (`veil audit` runs the same through Claude Code.)

    uv run pytest tests/test_llm_payload.py -s
"""

import os

import pytest

from veil.audit import CHINOOK, run_sdk, scenario
from veil.testing import Recorder, start_mock_llm, start_proxy, write_captures

OUT = os.path.join(os.path.dirname(__file__), "..", "captures", "sdk")
pytestmark = pytest.mark.skipif(not os.path.exists(CHINOOK), reason="datasets/chinook.sqlite not downloaded")


def test_what_the_llm_receives():
    veil, real_values, ws = scenario(os.path.abspath(OUT))
    rec = Recorder()
    llm = start_mock_llm(db_path="chinook.sqlite")
    px = start_proxy(veil, f"http://127.0.0.1:{llm.server_port}", rec)
    try:
        final, executed = run_sdk(f"http://127.0.0.1:{px.server_port}", "sk-ant-mock", "claude-opus-5-5", ws)
    finally:
        px.shutdown(); llm.shutdown()
    summary = write_captures(OUT, veil, rec.exchanges, real_values, "What the LLM received — SDK loop, fake LLM")
    print(f"\n[veil] {summary}")

    # 1. Nothing real ever reached the model, and the guard had nothing to repair.
    assert summary["requests"] == 3 and summary["leaks"] == {} and summary["guard_repairs"] == 0
    # 2. ...but the agent still worked on real data locally (tools ran with rehydrated values).
    assert executed[0]["tool"] == "Bash" and "leonekohler@surfeu.de" in executed[0]["input"]["command"]
    assert executed[1] == {"tool": "Read", "input": {"file_path": os.path.join(ws, "app.log")}}
    assert "leonekohler@surfeu.de" in final and "duplicate" in final
    # 3. The model only ever wrote valid tokens.
    assert summary["mangled_tokens"] == []
