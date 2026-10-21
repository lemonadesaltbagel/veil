"""Cloud-provider formats for Claude Code: Amazon Bedrock and Google Vertex (Agent Platform).

Both carry Anthropic Messages bodies (+ an `anthropic_version` body field), so the
Anthropic redaction applies unchanged. Differences handled here:

* routing  Bedrock `/model/{id}/invoke[-with-response-stream]`, `/model/{id}/count-tokens`;
           Vertex `.../publishers/anthropic/models/{m}:streamRawPredict|:rawPredict`.
* streams  Vertex streams SSE (reuses StreamRewriter). Bedrock streams the binary
           `application/vnd.amazon.eventstream`: frames of prelude + headers + JSON
           payload {"bytes": base64(event)} + CRC32s. veil decodes each frame, rewrites
           the inner Anthropic event, and re-encodes it with fresh CRCs -- Claude Code
           can't parse SSE in its place, and the content-type must pass unchanged.
* auth     Clients skip their own signing (CLAUDE_CODE_SKIP_BEDROCK_AUTH /
           CLAUDE_CODE_SKIP_VERTEX_AUTH) and veil adds credentials *after* redaction,
           because a client SigV4 signature covers the body veil must change.
"""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import subprocess
import time
import zlib

BEDROCK_PATH = re.compile(r"^/model/(?P<model>[^/]+)/(?P<op>invoke|invoke-with-response-stream|count-tokens)$")
VERTEX_PATH = re.compile(r"/publishers/anthropic/models/(?P<model>[^/:]+):(?P<op>streamRawPredict|rawPredict)$")


def route(path: str) -> str | None:
    p = path.split("?")[0]
    if BEDROCK_PATH.match(p):
        return "bedrock"
    if VERTEX_PATH.search(p):
        return "vertex"
    return None


def is_count_tokens(path: str) -> bool:
    p = path.split("?")[0]
    return p.endswith("/count-tokens") or "count-tokens:rawPredict" in p


# -- AWS event stream (application/vnd.amazon.eventstream) --------------------------

def encode_frame(headers: dict[str, str], payload: bytes) -> bytes:
    hb = b""
    for name, value in headers.items():
        n, v = name.encode(), value.encode()
        hb += struct.pack(">B", len(n)) + n + struct.pack(">BH", 7, len(v)) + v  # 7 = string
    total = 12 + len(hb) + len(payload) + 4
    prelude = struct.pack(">II", total, len(hb))
    head = prelude + struct.pack(">I", zlib.crc32(prelude)) + hb + payload
    return head + struct.pack(">I", zlib.crc32(head))


def _parse_headers(raw: bytes) -> dict:
    out, i = {}, 0
    while i < len(raw):
        n = raw[i]; name = raw[i + 1:i + 1 + n].decode(); i += 1 + n
        t = raw[i]; i += 1
        if t == 7 or t == 6:  # string / bytes
            ln = struct.unpack(">H", raw[i:i + 2])[0]; i += 2
            val = raw[i:i + ln]; i += ln
            out[name] = val.decode() if t == 7 else val
        elif t in (0, 1):     # bool true/false
            out[name] = t == 0
        else:                 # fixed-size ints/timestamps/uuid: skip by size
            size = {2: 1, 3: 2, 4: 4, 5: 8, 8: 8, 9: 16}[t]
            out[name] = raw[i:i + size]; i += size
    return out


class FrameDecoder:
    def __init__(self):
        self.buf = b""

    def feed(self, data: bytes) -> list[tuple[dict, bytes]]:
        self.buf += data
        frames = []
        while len(self.buf) >= 12:
            total, hlen = struct.unpack(">II", self.buf[:8])
            if struct.unpack(">I", self.buf[8:12])[0] != zlib.crc32(self.buf[:8]):
                raise ValueError("eventstream prelude CRC mismatch")
            if len(self.buf) < total:
                break
            msg, self.buf = self.buf[:total], self.buf[total:]
            if struct.unpack(">I", msg[-4:])[0] != zlib.crc32(msg[:-4]):
                raise ValueError("eventstream message CRC mismatch")
            frames.append((_parse_headers(msg[12:12 + hlen]), msg[12 + hlen:-4]))
        return frames


def chunk_frame(event: dict) -> bytes:
    payload = json.dumps({"bytes": base64.b64encode(json.dumps(event, ensure_ascii=False).encode()).decode()})
    return encode_frame({":event-type": "chunk", ":content-type": "application/json", ":message-type": "event"},
                        payload.encode())


def chunk_event(headers: dict, payload: bytes) -> dict | None:
    """The Anthropic event inside a Bedrock `chunk` frame (None for other frames)."""
    if headers.get(":message-type") != "event" or headers.get(":event-type") != "chunk":
        return None
    return json.loads(base64.b64decode(json.loads(payload)["bytes"]))


# -- credentials injected after redaction ----------------------------------------------

_vertex_token: dict = {"value": None, "exp": 0.0}


def vertex_auth(headers: dict) -> dict:
    if any(k.lower() == "authorization" for k in headers):
        return headers
    token = os.environ.get("VEIL_VERTEX_TOKEN")
    if not token:
        if _vertex_token["value"] and time.time() < _vertex_token["exp"]:
            token = _vertex_token["value"]
        else:
            try:
                token = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True,
                                       timeout=30).stdout.strip() or None
            except OSError:
                token = None
            _vertex_token.update(value=token, exp=time.time() + 45 * 60)
    return {**headers, "authorization": f"Bearer {token}"} if token else headers


def bedrock_auth(method: str, url: str, headers: dict, body: bytes | None) -> dict:
    if any(k.lower() == "authorization" for k in headers):
        return headers
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):  # Bedrock API key
        return {**headers, "authorization": f"Bearer {os.environ['AWS_BEARER_TOKEN_BEDROCK']}"}
    try:  # SigV4 with the default AWS credential chain (pip install veil[bedrock])
        import botocore.session
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
    except ImportError:
        return headers
    creds = botocore.session.get_session().get_credentials()
    if creds is None:
        return headers
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    signed = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")}
    req = AWSRequest(method=method, url=url, data=body or b"", headers=signed)
    SigV4Auth(creds.get_frozen_credentials(), "bedrock", region).add_auth(req)
    return dict(req.headers.items())
