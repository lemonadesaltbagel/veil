"""Bedrock (binary eventstream) and Vertex (SSE) support."""

import base64
import json

import pytest

from veil import cloud


def test_routes():
    assert cloud.route("/model/us.anthropic.claude-opus-5-5/invoke-with-response-stream") == "bedrock"
    assert cloud.route("/model/anthropic.claude-x/invoke") == "bedrock"
    assert cloud.route("/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-x:streamRawPredict") == "vertex"
    assert cloud.route("/v1/messages") is None and cloud.route("/inference-profiles") is None
    assert cloud.is_count_tokens("/model/m/count-tokens")
    assert cloud.is_count_tokens("/v1/projects/p/locations/l/publishers/anthropic/models/count-tokens:rawPredict")


def test_eventstream_matches_aws_decoder_and_detects_corruption():
    botocore = pytest.importorskip("botocore.eventstream")
    ev = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Köhler"}}
    frame = cloud.chunk_frame(ev)
    buf = botocore.EventStreamBuffer(); buf.add_data(frame)
    (msg,) = list(buf)
    assert json.loads(base64.b64decode(json.loads(msg.payload)["bytes"])) == ev
    d = cloud.FrameDecoder()
    assert [cloud.chunk_event(h, p) for h, p in d.feed(frame[:5]) + d.feed(frame[5:])] == [ev]
    bad = bytearray(frame); bad[-10] ^= 0xFF  # flip a payload byte
    with pytest.raises(ValueError):
        cloud.FrameDecoder().feed(bytes(bad))


def test_credentials_injected_after_redaction(monkeypatch):
    monkeypatch.setenv("VEIL_VERTEX_TOKEN", "ya29.test")
    assert cloud.vertex_auth({"content-type": "application/json"})["authorization"] == "Bearer ya29.test"
    assert cloud.vertex_auth({"Authorization": "Bearer client"}) == {"Authorization": "Bearer client"}
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-api-key")
    assert cloud.bedrock_auth("POST", "https://x/model/m/invoke", {}, b"{}")["authorization"] == "Bearer bedrock-api-key"


def test_sigv4_signs_the_redacted_body(monkeypatch):
    pytest.importorskip("botocore")
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"); monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke"
    a = cloud.bedrock_auth("POST", url, {"content-type": "application/json"}, b'{"x": "user_ab12@example.test"}')
    b = cloud.bedrock_auth("POST", url, {"content-type": "application/json"}, b'{"x": "other"}')
    assert a["Authorization"].startswith("AWS4-HMAC-SHA256") and a["Authorization"] != b["Authorization"]
