"""Team secrets in a secrets manager instead of a hand-copied bundle.

    veil team export --to aws-sm://veil/team          (admin, once; again after a rotation)
    veil team join --from aws-sm://veil/team          (everyone; remembered in config.json)
    veil team sync                                     (re-read; on a new secret, old pseudonyms
                                                        are retired so open conversations still work)

References:
    op://VAULT/ITEM/FIELD                 1Password CLI (`op read`, `op item edit`)
    aws-sm://SECRET-ID[?region=R]         AWS Secrets Manager (botocore credential chain)
    gcp-sm://PROJECT/SECRET               Google Secret Manager (`gcloud secrets ...`)
    vault://MOUNT/PATH#FIELD              HashiCorp Vault KV v2 (VAULT_ADDR, VAULT_TOKEN or ~/.vault-token)
    env:NAME   file:/path

The value is the team bundle (pseudonym secret + allowlist; a passphrase layer is
optional here, since the manager controls access). Secrets never appear in argv: CLIs
receive them on stdin, HTTP APIs in the request body.
"""

from __future__ import annotations

import json
import os
import subprocess
from urllib.parse import parse_qs, urlparse

import httpx


class RefError(Exception):
    pass


def _run(cmd: list[str], stdin: str | None = None) -> str:
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise RefError(f"`{cmd[0]}` is not installed")
    if r.returncode != 0:
        raise RefError(f"`{cmd[0]}` failed: {r.stderr.strip()[:300]}")
    return r.stdout


def _vault(ref: str):
    u = urlparse(ref)
    mount, path = u.netloc, u.path.strip("/")
    field = u.fragment or "bundle"
    addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
    token = os.environ.get("VAULT_TOKEN")
    if not token and os.path.exists(os.path.expanduser("~/.vault-token")):
        token = open(os.path.expanduser("~/.vault-token")).read().strip()
    if not token:
        raise RefError("no Vault token (VAULT_TOKEN or ~/.vault-token)")
    client = httpx.Client(base_url=addr, headers={"X-Vault-Token": token}, timeout=30, trust_env=False)
    return client, f"/v1/{mount}/data/{path}", field


def _aws(ref: str):
    import botocore.session  # pip install "veil-proxy[bedrock]"
    u = urlparse(ref)
    q = parse_qs(u.query)
    region = (q.get("region") or [os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"])[0]
    client = botocore.session.get_session().create_client(
        "secretsmanager", region_name=region, endpoint_url=(q.get("endpoint") or [None])[0])
    return client, (u.netloc + u.path).strip("/")


def read(ref: str) -> str:
    scheme = ref.split(":", 1)[0]
    if scheme == "env":
        v = os.environ.get(ref[4:])
        if v is None:
            raise RefError(f"environment variable {ref[4:]} is not set")
        return v
    if scheme == "file":
        return open(ref[5:]).read().strip()
    if scheme == "op":
        return _run(["op", "read", ref]).strip()
    if scheme == "gcp-sm":
        project, secret = urlparse(ref).netloc, urlparse(ref).path.strip("/")
        return _run(["gcloud", "secrets", "versions", "access", "latest", f"--secret={secret}", f"--project={project}"]).strip()
    if scheme == "aws-sm":
        client, sid = _aws(ref)
        return client.get_secret_value(SecretId=sid)["SecretString"]
    if scheme == "vault":
        client, path, field = _vault(ref)
        with client:
            r = client.get(path)
        if r.status_code != 200:
            raise RefError(f"Vault {r.status_code} for {path}")
        return r.json()["data"]["data"][field]
    raise RefError(f"unsupported secret reference: {scheme}:")


def write(ref: str, value: str) -> None:
    scheme = ref.split(":", 1)[0]
    if scheme == "file":
        fd = os.open(ref[5:], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value)
        return
    if scheme == "op":  # op://VAULT/ITEM/FIELD -> an existing item's field, value from stdin via a template
        vault, item, field = urlparse(ref).netloc, *urlparse(ref).path.strip("/").split("/", 1)
        _run(["op", "item", "edit", item, f"--vault={vault}", "--template=/dev/stdin"],
             stdin=json.dumps({"fields": [{"label": field, "type": "CONCEALED", "value": value}]}))
        return
    if scheme == "gcp-sm":
        project, secret = urlparse(ref).netloc, urlparse(ref).path.strip("/")
        _run(["gcloud", "secrets", "versions", "add", secret, f"--project={project}", "--data-file=-"], stdin=value)
        return
    if scheme == "aws-sm":
        client, sid = _aws(ref)
        try:
            client.put_secret_value(SecretId=sid, SecretString=value)
        except client.exceptions.ResourceNotFoundException:
            client.create_secret(Name=sid, SecretString=value)
        return
    if scheme == "vault":
        client, path, field = _vault(ref)
        with client:
            r = client.post(path, json={"data": {field: value}})
        if r.status_code not in (200, 204):
            raise RefError(f"Vault {r.status_code} writing {path}")
        return
    raise RefError(f"cannot write to {scheme}: references")
