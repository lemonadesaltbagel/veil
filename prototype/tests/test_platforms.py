"""Microsoft Foundry and Claude Platform on AWS: Anthropic Messages under /foundry and
/anthropic-aws, redacted like any other request; credentials forwarded, or added by veil
after redaction (SigV4 covers the body)."""

import json

import httpx
import pytest

from veil import cloud
from veil.detect import KnownValues
from veil.engine import Veil
from veil.vault import Vault
from veil_dev.testing import Recorder, start_mock_llm, start_proxy

REAL = "leonekohler@surfeu.de"


@pytest.fixture
def stack():
    known = KnownValues(); known.add(REAL, "email", "c:2")
    veil = Veil(Vault(":memory:", b"p"), known)
    llm = start_mock_llm()
    px = start_proxy(veil, f"http://127.0.0.1:{llm.server_port}", Recorder())
    yield f"http://127.0.0.1:{px.server_port}", llm
    px.shutdown(); llm.shutdown()


def _post(url, headers):
    body = {"model": "claude-sonnet", "max_tokens": 50, "messages": [{"role": "user", "content": f"why does {REAL} fail?"}]}
    with httpx.Client(trust_env=False) as c:
        return c.post(url, json=body, headers=headers)


def test_foundry_key_passes_through(stack):
    url, llm = stack
    r = _post(url + "/foundry/v1/messages", {"x-api-key": "foundry-key", "anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    path, headers, _ = llm.requests[-1]
    assert path == "/v1/messages" and headers["x-api-key"] == "foundry-key"


def test_anthropic_aws_signs_after_redaction_and_keeps_workspace(stack, monkeypatch):
    url, llm = stack
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    monkeypatch.setenv("VEIL_ANTHROPIC_AWS_SIGV4_SERVICE", "aws-external-anthropic")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("ANTHROPIC_AWS_API_KEY", raising=False)
    r = _post(url + "/anthropic-aws/v1/messages", {"anthropic-workspace-id": "wrkspc_01", "anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    path, headers, _ = llm.requests[-1]
    assert path == "/v1/messages" and headers["anthropic-workspace-id"] == "wrkspc_01"
    assert headers["authorization"].startswith(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") and "/us-east-1/aws-external-anthropic/aws4_request" in headers["authorization"]


def test_aws_service_and_region_come_from_the_host(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    for var in ("AWS_REGION", "VEIL_ANTHROPIC_AWS_SIGV4_SERVICE", "ANTHROPIC_AWS_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    h = cloud.anthropic_aws_auth("POST", "https://aws-external-anthropic.eu-west-1.api.aws/v1/messages", {}, b"{}")
    assert "/eu-west-1/aws-external-anthropic/aws4_request" in h["Authorization"]
    monkeypatch.setenv("ANTHROPIC_AWS_API_KEY", "wk")  # a workspace key instead of SigV4
    assert cloud.anthropic_aws_auth("POST", "https://x/v1/messages", {}, b"{}") == {"x-api-key": "wk"}
    assert cloud.split_prefix("/foundry/v1/messages?beta=true") == ("foundry", "/v1/messages?beta=true")
    assert cloud.split_prefix("/v1/messages") == (None, "/v1/messages")


def test_redacted_before_it_reaches_either_platform(stack):
    url, llm = stack
    for prefix in ("/foundry", "/anthropic-aws"):
        r = _post(url + prefix + "/v1/messages", {"x-api-key": "k"})
        assert r.status_code == 200
        path, headers, raw = llm.requests[-1]
        assert REAL not in raw.decode() and "@example.test" in raw.decode()  # what the platform received
        assert REAL not in json.dumps(headers)
