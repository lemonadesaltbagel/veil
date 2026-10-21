"""Automatic re-seeding: new customers become known values without re-running `veil seed`."""

import base64
import json
import os
import sqlite3
import time
import uuid

import pytest

from veil.detect import KnownValues
from veil.engine import Veil
from veil.reseed import Reseeder, fingerprint
from veil.sources import seed
from veil.vault import Vault


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def _veil(*sources):
    known = KnownValues()
    for s in sources:
        seed(known, s)
    return Veil(Vault(":memory:", b"s"), known)


def test_new_sqlite_customer_is_picked_up(tmp_path):
    db = tmp_path / "app.db"
    con = sqlite3.connect(db)
    con.execute("create table users (id integer primary key, full_name text, email text)")
    con.execute("insert into users values (1, 'Leonie Kohler', 'leonie@shop.example.net')")
    con.commit()
    veil = _veil(str(db))
    saved = []
    rs = Reseeder(veil, [str(db)], interval=0.1, save=saved.append, log=open(os.devnull, "w"))
    rs.check_once()  # baseline fingerprint
    assert "Ingrid Holm" in veil.redact("ticket from Ingrid Holm")  # not known yet
    con.execute("insert into users values (2, 'Ingrid Holm', 'ingrid.holm@fjord-mail.no')")
    con.commit()
    rs.start()
    try:
        assert _wait(lambda: "Ingrid Holm" not in veil.redact("ticket from Ingrid Holm"))
    finally:
        rs.stop()
    assert saved and "Ingrid Holm" in saved[-1]._entries  # persisted for hook processes


def test_files_source_and_unreachable_source(tmp_path):
    fx = tmp_path / "fixtures"; fx.mkdir()
    (fx / "users.json").write_text(json.dumps([{"id": 1, "email": "a.one@corp-mail.org", "full_name": "Anna One"}]))
    veil = _veil(str(fx))
    rs = Reseeder(veil, [str(fx), "postgresql://nobody@127.0.0.1:1/none"], interval=0.1, log=open(os.devnull, "w"))
    rs.check_once()
    (fx / "users.json").write_text(json.dumps([{"id": 1, "email": "a.one@corp-mail.org", "full_name": "Anna One"},
                                               {"id": 2, "email": "b.two@corp-mail.org", "full_name": "Bruno Two"}]))
    time.sleep(0.01)
    rs.check_once()  # unreachable postgres is reported, not fatal
    assert "Bruno Two" not in veil.redact("Bruno Two")


def test_sources_are_remembered_encrypted(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    from veil import state
    url = "postgresql://app:s3cret@db.internal/app"
    state.remember_sources([url, "fixtures"])
    state.remember_sources([url])  # no duplicates
    assert state.load_sources() == [url, os.path.abspath("fixtures")]
    assert b"s3cret" not in (tmp_path / "sources.enc").read_bytes()


LIVE = {
    "postgres": "postgresql://postgres@127.0.0.1:55432/chinook",
    "mysql": "mysql://root@127.0.0.1:53306/Chinook",
    "redis": "redis://127.0.0.1:56379/0",
    "mongo": "mongodb://127.0.0.1:57017/sample_mflix",
}


@pytest.mark.parametrize("kind", list(LIVE))
def test_live_fingerprint_changes_on_insert(kind):
    url = LIVE[kind]
    try:
        before = fingerprint(url)
    except Exception as e:
        pytest.skip(f"{kind} not available: {type(e).__name__}")
    tag = uuid.uuid4().hex[:8]
    email = f"reseed.{tag}@newcustomer.example.org"
    if kind == "postgres":
        import psycopg
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("insert into customer (customer_id, first_name, last_name, email) values "
                      "((select max(customer_id) + 1 from customer), 'Reseed', %s, %s)", (tag, email))
        undo = lambda: psycopg.connect(url, autocommit=True).execute("delete from customer where email = %s", (email,))
    elif kind == "mysql":
        import pymysql
        c = pymysql.connect(host="127.0.0.1", port=53306, user="root", database="Chinook", autocommit=True)
        c.cursor().execute("insert into Customer (CustomerId, FirstName, LastName, Email) "
                           "select max(CustomerId) + 1, 'Reseed', %s, %s from Customer", (tag, email))
        undo = lambda: c.cursor().execute("delete from Customer where Email = %s", (email,))
    elif kind == "redis":
        import redis
        r = redis.Redis.from_url(url)
        r.hset(f"user:{tag}", mapping={"email": email, "first_name": "Reseed"})
        undo = lambda: r.delete(f"user:{tag}")
    else:
        from pymongo import MongoClient
        coll = MongoClient(url)["sample_mflix"]["users"]
        coll.insert_one({"name": f"Reseed {tag}", "email": email})
        undo = lambda: coll.delete_one({"email": email})
    try:
        time.sleep(0.6 if kind == "postgres" else 0.1)  # Postgres flushes table stats asynchronously
        assert _wait(lambda: fingerprint(url) != before, timeout=8)
    finally:
        undo()
