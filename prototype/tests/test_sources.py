"""Seeding from database structures. Unit tests run everywhere; integration
tests run against live databases when reachable (VEIL_TEST_PG / _MYSQL / _MONGO)."""

import os
import re

import pytest

from veil.detect import KnownValues
from veil.engine import Veil
from veil.sources import seed
from veil.sources.core import classify_comment, classify_name, classify_values, extract, flatten
from veil.vault import Vault

HERE = os.path.dirname(__file__)
PG = os.environ.get("VEIL_TEST_PG", "postgresql://postgres:veil@127.0.0.1:55432/chinook")
MYSQL = os.environ.get("VEIL_TEST_MYSQL", "mysql://root@127.0.0.1:53306/Chinook")


def code_of(token: str) -> str:
    m = re.match(r"(?:user[_ ]|first_|last_)([a-z2-9]+)|([a-z2-9]+) example street", token, re.I)
    return (m.group(1) or m.group(2)).lower()


# -- unit -----------------------------------------------------------------------

@pytest.mark.parametrize("container,path,kind", [
    ("app.accounts", "profile.name.given", "first_name"),
    ("app.accounts", "profile.name.family", "last_name"),
    ("app.accounts", "profile.emails[]", "email"),
    ("app.accounts", "profile.phones[].number", "phone"),
    ("app.accounts", "profile.address.street", "address"),
    ("app.accounts", "profile.address.city", None),
    ("app.events", "payload.actor.ip", "ipv4"),
    ("tenant_acme.users", "work_email", "email"),
    ("products", "name", None),                   # a product name is not a person
    ("users", "name", "name"),
    ("app.accounts", "password_hash", "secret"),
    ("orders", "total", None),
    ("users", "ip_address", "ipv4"),              # not a street address
    ("devices", "mac_address", None),
    ("users", "email_address", "email"),
    ("users", "billing_address", "address"),
    ("clients", "courriel", "email"),              # pg_anonymizer dictionary (French)
    ("clients", "prenom", "first_name"),
    ("clients", "telephone_portable", "phone"),
    ("clients", "client_id", None),                # opaque ids are not pseudonymised
    ("users", "uid", None),
])
def test_classify_paths(container, path, kind):
    assert classify_name(container, path) == kind


def test_native_masking_labels():
    from veil.sources.core import classify_label
    assert classify_label("MASKED WITH FUNCTION anon.fake_email()") == "email"
    assert classify_label("MASKED WITH FUNCTION anon.fake_last_name()") == "last_name"
    assert classify_label("MASKED WITH FUNCTION anon.partial(phone, 2, $$******$$, 2)") == "phone"
    assert classify_label("MASKED WITH VALUE NULL") == "pii"
    assert classify_label("some other label") is None


def test_comments_values_and_paths():
    assert classify_comment("pii:email - secondary contact") == "email"
    assert classify_comment("GDPR personal data") == "pii"
    assert classify_comment("cached total") is None
    assert classify_values(["a@x.io", "b@y.io", "c@z.io", "d@w.io", "e@v.io", "n/a"]) == "email"
    assert classify_values(["opt-in"] * 10) is None
    assert classify_values(["1581151007", "1581151999", "1600000000", "1612345678", "1599999999"]) is None
    assert classify_values(["+1 415 555 0100", "(212) 555-0148", "+49 711 2842222", "+44 20 7946 0958",
                            "415-555-0199"]) == "phone"
    doc = {"name": {"given": "Ana"}, "phones": [{"type": "m", "number": "+1 555 123 4567"}], "tags": ["x"]}
    assert dict(flatten(doc))["phones[].number"] == "+1 555 123 4567"
    assert extract({"profile": '{"emails": ["a@x.io", "b@x.io"]}'}, "profile.emails[]") == ["a@x.io", "b@x.io"]


def test_sqlite_grouping_follows_identity_not_association():
    if not os.path.exists(os.path.join(HERE, "..", "datasets", "chinook.sqlite")):
        pytest.skip("datasets not downloaded (scripts/fetch_datasets.sh)")
    known = KnownValues()
    report = seed(known, os.path.join(HERE, "..", "datasets", "chinook.sqlite"))
    v = Veil(Vault(":memory:", b"s"), known)
    # Customer 1 (Luís Gonçalves) has SupportRepId 3 (Jane Peacock): different people.
    assert code_of(v.redact("luisg@embraer.com.br")) != code_of(v.redact("jane@chinookcorp.com"))
    # Invoice.BillingAddress is the customer's own address: same person, same code.
    assert code_of(v.redact("luisg@embraer.com.br")) == code_of(v.redact("Av. Brigadeiro Faria Lima, 2170"))
    assert {f.container for f in report.fields} == {"Customer", "Employee", "Invoice"}


# -- integration ------------------------------------------------------------------

def _seeded(uri):
    known = KnownValues()
    try:
        report = seed(known, uri)
    except Exception as e:  # not reachable / driver missing
        pytest.skip(f"{uri.split('://')[0]} not available: {type(e).__name__}")
    return report, Veil(Vault(":memory:", b"s"), known)


def test_postgres_structures():
    report, v = _seeded(PG)
    fields = {f"{f.container}.{f.path}": (f.kind, f.signal) for f in report.fields}
    assert fields["app.accounts.contact"] == ("email", "comment")           # COMMENT ON COLUMN
    assert fields["app.newsletter_imports.c1"] == ("email", "values")       # value sampling
    assert fields["app.accounts.profile.name.given"][0] == "first_name"      # JSONB path
    assert fields["app.accounts.aliases[]"][0] == "username"                # text[]
    assert fields["app.accounts.last_login_ip"][0] == "ipv4"                # inet
    assert fields["tenant_acme.users.work_email"][0] == "email"             # schema per tenant
    assert "app.newsletter_imports.c2" not in fields
    assert not any(k.startswith("app.v_customer_contacts") for k in fields)  # views are not tables
    # One person across customer, accounts (unique FK), JSONB profile, arrays:
    leonie = ["leonekohler@surfeu.de", "Leonie Köhler", "leonie.2", "leonie2@mailbox.org", "cust2_köh",
              "Theodor-Heuss-Straße 34"]
    assert len({code_of(v.redact(x)) for x in leonie}) == 1
    out = v.redact(" ".join(leonie))
    assert v.rehydrate(out) == " ".join(leonie)


def test_mysql_structures():
    report, v = _seeded(MYSQL)
    kinds = {f"{f.container}.{f.path}": f.kind for f in report.fields}
    assert kinds["Customer.Email"] == "email" and kinds["Employee.LastName"] == "last_name"
    assert code_of(v.redact("leonekohler@surfeu.de")) == code_of(v.redact("Theodor-Heuss-Straße 34"))


def test_mongo_structures_on_mflix():
    """Real sample_mflix documents in an in-memory MongoDB (mongomock): nested
    JWT claims, denormalised comment copies, `user_id` that holds an email."""
    mongomock = pytest.importorskip("mongomock")
    from bson import json_util
    from veil.sources import seed_mongo
    client = mongomock.MongoClient()
    for name in ("users", "sessions", "comments"):
        path = os.path.join(HERE, "..", "datasets", "mflix", f"{name}.json")
        if not os.path.exists(path):
            pytest.skip("datasets/mflix not downloaded")
        client.sample_mflix[name].insert_many([json_util.loads(l) for l in open(path) if l.strip()])
    known = KnownValues()
    report = seed_mongo(known, None, "sample_mflix", client=client)
    kinds = {f"{f.container}.{f.path}": f.kind for f in report.fields}
    assert kinds["users.email"] == "email" and kinds["users.name"] == "name"
    assert kinds["users.password"] == "secret"
    assert kinds["sessions.jwt.$jwt.identity.email"] == "email"
    v = Veil(Vault(":memory:", b"s"), known)
    out = v.redact("Ned Stark <sean_bean@gameofthron.es>")
    assert "Stark" not in out and code_of(out.split(" <")[0]) == code_of(out.split("<")[1])


def test_redis_key_patterns_and_types():
    from veil.sources.kv import key_pattern
    assert key_pattern("user:42") == "user:{id}"
    assert key_pattern("sess:9f1c2a7b3e4d5f60718293a4b5c6d7e8") == "sess:{id}"
    assert key_pattern("user:42:email") == "user:{id}:email"
    assert key_pattern("newsletter:subscribers") == "newsletter:subscribers"


def test_redis_live():
    report, v = _seeded(os.environ.get("VEIL_TEST_REDIS", "redis://127.0.0.1:56379/0"))
    kinds = {f"{f.container}.{f.path}": (f.kind, f.signal) for f in report.fields}
    assert kinds["redis:user:{id}.ip_address"][0] == "ipv4"
    assert "redis:user:{id}.last_login" not in kinds
    assert kinds["redis:newsletter:subscribers.subscribers[]"] == ("email", "values")


def test_fixture_files(tmp_path):
    import json as _json
    (tmp_path / "users.json").write_text(_json.dumps([                       # Django fixture
        {"model": "auth.user", "pk": 1, "fields": {"username": "dkowalski", "email": "dana.k@corp.pl",
                                                   "first_name": "Dana", "last_name": "Kowalski"}}]))
    (tmp_path / "leads.csv").write_text("id,full_name,contact\n7,Ravi Menon,ravi.menon@mail.in\n"
                                        "8,Ana Lima,ana@lima.br\n9,Bo Chen,bo@chen.cn\n10,Ed Ruiz,ed@ruiz.mx\n"
                                        "11,Ida Berg,ida@berg.se\n")
    (tmp_path / "export.json").write_text(                                     # mongoexport: JSONL in .json
        '{"_id": {"$oid": "59b99db4cfa9a34dcd7885b6"}, "name": "Ned Stark", "email": "ned@winterfell.north"}\n'
        '{"_id": {"$oid": "59b99db4cfa9a34dcd7885b7"}, "name": "Arya Stark", "email": "arya@winterfell.north"}\n')
    known = KnownValues()
    report = seed(known, str(tmp_path))
    found = {f"{f.container}.{f.path}": (f.kind, f.signal) for f in report.fields}
    assert found["auth.user.username"][0] == "username" and found["auth.user.last_name"][0] == "last_name"
    assert found["leads.contact"] == ("email", "values") and found["leads.full_name"][0] == "name"
    assert found["export.email"][0] == "email"
    v = Veil(Vault(":memory:", b"s"), known)
    assert "Kowalski" not in v.redact("Dana Kowalski <dana.k@corp.pl>") and "Ned" not in v.redact("Ned Stark")


def test_mongo_live():
    report, v = _seeded(os.environ.get("VEIL_TEST_MONGO", "mongodb://127.0.0.1:57017/sample_mflix"))
    kinds = {f"{f.container}.{f.path}": f.kind for f in report.fields}
    if not kinds:
        pytest.skip("mongodb reachable but sample_mflix not loaded")
    assert kinds["users.email"] == "email" and kinds["users.password"] == "secret"
    assert kinds["sessions.jwt.$jwt.identity.email"] == "email"
    out = v.redact("Ned Stark <sean_bean@gameofthron.es>")
    assert "Stark" not in out and code_of(out.split(" <")[0]) == code_of(out.split("<")[1])
