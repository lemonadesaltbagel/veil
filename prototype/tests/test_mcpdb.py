"""veil mcp-db: pseudonyms become bound parameters (never SQL text); reads only;
results pseudonymised; MCP over stdio."""

import base64
import io
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from veil import state
from veil.detect import KnownValues
from veil.engine import Veil
from veil.mcpdb import Server, ToolError, open_source, prepare_sql, restore_filter
from veil.vault import Vault

HOSTILE = "x'); DROP TABLE users; --"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "app.db"
    con = sqlite3.connect(path)
    con.execute("create table users (id integer primary key, name text, email text, note text)")
    con.executemany("insert into users values (?, ?, ?, ?)", [
        (1, "Leonie Köhler", "leonekohler@surfeu.de", "prefers email"),
        (2, HOSTILE, "bobby@tables.example.org", "O'Brien's account"),
        (3, "Zoë 100% Real", "zoe@pct.example.org", "")])
    con.commit()
    known = KnownValues(min_len=1)
    for i, (n, e) in enumerate([("Leonie Köhler", "leonekohler@surfeu.de"), (HOSTILE, "bobby@tables.example.org"),
                                ("Zoë 100% Real", "zoe@pct.example.org")], 1):
        known.add(n, "name", f"users:{i}"); known.add(e, "email", f"users:{i}")
    veil = Veil(Vault(":memory:", b"m"), known)
    return str(path), veil


def test_literals_with_pseudonyms_become_parameters(db):
    _, veil = db
    tok = veil.redact("leonekohler@surfeu.de")
    sql, params = prepare_sql(veil, f"SELECT * FROM users WHERE email = '{tok}' AND note <> 'x';")
    assert sql == "SELECT * FROM users WHERE email = ? AND note <> 'x'" and params == ["leonekohler@surfeu.de"]
    sql, params = prepare_sql(veil, f"SELECT 1 FROM t WHERE a LIKE '%{tok}%' AND b % 2 = 0", "format")
    assert sql == "SELECT 1 FROM t WHERE a LIKE %s AND b %% 2 = 0" and params == ["%leonekohler@surfeu.de%"]


@pytest.mark.parametrize("sql,msg", [
    ("DELETE FROM users", "read-only"),
    ("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", "(?i)delete"),
    ("SELECT * INTO backup FROM users", "(?i)into"),
    ("SELECT 1; DROP TABLE users", "one statement"),
    ("SELECT 1 /* ; */ ; UPDATE users SET name = 'x'", "one statement"),
    ("SELECT * FROM users FOR UPDATE", "(?i)update"),
    ("PRAGMA writable_schema = 1", "schema PRAGMAs"),
    ("PRAGMA journal_mode(DELETE)", "schema PRAGMAs"),
])
def test_writes_are_refused(db, sql, msg):
    _, veil = db
    with pytest.raises(ToolError, match=msg):
        prepare_sql(veil, sql)


def test_schema_pragmas_are_allowed(db):
    _, veil = db
    assert prepare_sql(veil, "PRAGMA table_info(users)") == ("PRAGMA table_info(users)", [])


def test_pseudonyms_outside_literals_and_fragments_are_refused(db):
    _, veil = db
    tok = veil.redact("leonekohler@surfeu.de")
    with pytest.raises(ToolError, match="inside string literals"):
        prepare_sql(veil, f"SELECT * FROM users WHERE email = {tok}")
    code = tok.split("@")[0].split("_")[1]
    with pytest.raises(ToolError, match="part of a pseudonym"):
        prepare_sql(veil, f"SELECT * FROM users WHERE email LIKE '%{code}%'")


def test_query_by_pseudonym_finds_the_real_row_and_returns_pseudonyms(db):
    path, veil = db
    srv = Server(veil, open_source(path))
    for real in ("leonekohler@surfeu.de", "bobby@tables.example.org", "zoe@pct.example.org"):
        tok = veil.redact(real)
        out = srv.call("query", {"sql": f"SELECT id, name, email, note FROM users WHERE email = '{tok}'"})
        assert "(1 row)" in out and tok in out and real not in out
    out = srv.call("query", {"sql": f"SELECT count(*) FROM users WHERE name = '{veil.redact(HOSTILE)}'"})
    assert out.splitlines()[1] == "1"                              # the hostile value matched as data
    assert "Köhler" not in srv.call("query", {"sql": "SELECT * FROM users"})
    assert srv.call("query", {"sql": "SELECT count(*) FROM users"}).splitlines()[1] == "3"  # table intact


def test_read_only_even_past_the_keyword_check(db):
    path, _ = db
    src = open_source(path)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        src.run("DELETE FROM users", [], 10)


def test_mcp_protocol_over_stdio(db):
    path, veil = db
    tok = veil.redact("leonekohler@surfeu.de")
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "query", "arguments": {
                "sql": f"SELECT name FROM users WHERE email = '{tok}'"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "query", "arguments": {"sql": "DROP TABLE users"}}}]
    out = io.StringIO()
    Server(veil, open_source(path)).serve(io.StringIO("\n".join(map(json.dumps, msgs)) + "\n"), out)
    replies = [json.loads(l) for l in out.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3, 4]               # no reply to the notification
    assert replies[0]["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert {t["name"] for t in replies[1]["result"]["tools"]} == {"query", "list_tables", "describe_table"}
    text = replies[2]["result"]["content"][0]["text"]
    assert not replies[2]["result"]["isError"] and "First_" in text and "Leonie" not in text
    assert replies[3]["result"]["isError"] and "read-only" in replies[3]["result"]["content"][0]["text"]


def test_cli_server_uses_the_shared_vault(db, tmp_path, monkeypatch):
    path, _ = db
    env = {**os.environ, "VEIL_HOME": str(tmp_path / "home"),
           "VEIL_VAULT_KEY": base64.b64encode(b"v" * 32).decode(), "VEIL_TOKEN_SECRET": base64.b64encode(b"t" * 32).decode()}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    v = state.load()
    v.known.add("leonekohler@surfeu.de", "email", "users:1")
    state.save_known(v.known, v.vault.cipher)
    tok = v.redact("leonekohler@surfeu.de")                       # allocated by "the proxy"
    state.remember_sources([path], v.vault.cipher)
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "query", "arguments": {
                "sql": f"SELECT id FROM users WHERE email = '{tok}'"}}}]
    p = subprocess.run([sys.executable, "-m", "veil.cli", "mcp-db", "--source", "0"], env=env, timeout=60,
                       input="\n".join(map(json.dumps, msgs)) + "\n", capture_output=True, text=True)
    replies = [json.loads(l) for l in p.stdout.splitlines()]        # stdout is pure protocol
    assert replies[1]["result"]["content"][0]["text"].splitlines()[1] == "1", p.stderr


def test_mongo_filters_are_restored_structurally(db):
    _, veil = db
    tok = veil.redact("leonekohler@surfeu.de")
    f = restore_filter(veil, {"email": tok, "$or": [{"note": {"$regex": f"^{tok}"}}]})
    assert f == {"email": "leonekohler@surfeu.de", "$or": [{"note": {"$regex": "^leonekohler@surfeu\\.de"}}]}
    with pytest.raises(ToolError, match=r"\$where"):
        restore_filter(veil, {"$where": "sleep(1000)"})
    with pytest.raises(ToolError, match=r"\$out"):
        restore_filter(veil, [{"$match": {}}, {"$out": "copy"}])


LIVE = {"postgres": "postgresql://postgres@127.0.0.1:55432/chinook", "mysql": "mysql://root@127.0.0.1:53306/Chinook",
        "mongo": "mongodb://127.0.0.1:57017/sample_mflix"}


@pytest.mark.parametrize("kind", ["postgres", "mysql"])
def test_live_sql(kind):
    try:
        src = open_source(LIVE[kind])
    except Exception as e:
        pytest.skip(f"{kind} not available: {type(e).__name__}")
    known = KnownValues()
    known.add("leonekohler@surfeu.de", "email", "c:2")
    veil = Veil(Vault(":memory:", b"l"), known)
    tok = veil.redact("leonekohler@surfeu.de")
    table, col = ("customer", "email") if kind == "postgres" else ("Customer", "Email")
    out = Server(veil, src).call("query", {"sql": f"SELECT {col} FROM {table} WHERE {col} = '{tok}'"})
    assert "(1 row)" in out and "leonekohler" not in out
    with pytest.raises(Exception, match="(?i)read.only"):
        src.run(f"DELETE FROM {table} WHERE 1 = 0", [], 1)       # the connection itself refuses writes


def test_live_mongo():
    try:
        src = open_source(LIVE["mongo"])
        src.client.admin.command("ping")
    except Exception as e:
        pytest.skip(f"mongo not available: {type(e).__name__}")
    user = src.db.users.find_one({}, {"email": 1, "name": 1})
    known = KnownValues()
    known.add(user["email"], "email", "u:1"); known.add(user["name"], "name", "u:1")
    veil = Veil(Vault(":memory:", b"g"), known)
    srv = Server(veil, src)
    out = srv.call("find", {"collection": "users", "filter": {"email": veil.redact(user["email"])}, "projection": {"_id": 0}})
    assert veil.redact(user["name"]) in out and user["email"] not in out and user["name"] not in out
    assert srv.call("count", {"collection": "users", "filter": {"email": veil.redact(user["email"])}}) == "1"


@pytest.mark.skipif(sys.platform == "win32", reason="fake `claude` is a shell script")
def test_init_registers_the_tool_without_credentials(db, tmp_path, monkeypatch):
    path, _ = db
    bin_dir, log = tmp_path / "bin", tmp_path / "claude-args.txt"
    bin_dir.mkdir()
    (bin_dir / "claude").write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
    (bin_dir / "claude").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("VEIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    from veil import cli
    project = tmp_path / "proj"; project.mkdir()
    cli.main(["init", str(project), "--no-detect", "--no-hooks", "--port", "1", "--mcp",
              "--source", "postgresql://app:s3cret@127.0.0.1:1/shop", "--source", path])
    calls = log.read_text().splitlines()
    assert len(calls) == 2 and "s3cret" not in log.read_text()
    assert calls[0].startswith("mcp add veil-db --scope local -e VEIL_HOME=") and calls[0].endswith("mcp-db --source 0")
    assert calls[1].startswith("mcp add veil-db-2 ") and calls[1].endswith("mcp-db --source 1")
