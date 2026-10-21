"""Seeding hints from application code: ORM schemas and annotations say which fields are
personal even when the column name doesn't (backup_contact, mrn, recovery)."""

import base64
import json

from veil import cli, state
from veil.detect import KnownValues
from veil.sources import core, schema, seed

PRISMA = '''
model User {
  id        Int     @id
  /// @pii email
  contact   String  @map("contact_addr")
  pager     String  // pii: phone
  secretQ   String  /// @encrypted
  bio       String
  @@map("users")
}
'''
DJANGO = '''
from django.db import models

class Customer(models.Model):
    backup_contact = models.EmailField()
    last_ip = models.GenericIPAddressField(null=True)
    notes = models.TextField()  # pii
    plan = models.CharField(max_length=20)
'''
SQLA = '''
class Lead(Base):
    __tablename__ = "leads"
    reach = Column("reach_addr", EmailType)
    score = Column(Integer)
'''
RAILS_SCHEMA = '''
ActiveRecord::Schema[7.1].define(version: 1) do
  create_table "patients", force: :cascade do |t|
    t.string "mrn" # pii
    t.string "ward"
  end
end
'''
RAILS_MODEL = '''
class Patient < ApplicationRecord
  encrypts :ssn_last4, deterministic: true
  self.filter_attributes += [:diagnosis]
end
'''
OPENAPI = {"openapi": "3.1.0", "components": {"schemas": {"Member": {"properties": {
    "contact": {"type": "string", "format": "email"}, "backup": {"type": "string", "x-pii": "phone"},
    "nickname": {"type": "string"}}}}}}
PROTO = '''
message Account {
  string recovery = 1 [debug_redact = true];
  string handle = 2; // pii: username
  int32 tier = 3;
}
'''


def make_project(root):
    (root / "prisma").mkdir(parents=True)
    (root / "prisma" / "schema.prisma").write_text(PRISMA)
    (root / "shop").mkdir()
    (root / "shop" / "models.py").write_text(DJANGO)
    (root / "crm.py").write_text(SQLA)
    (root / "db").mkdir()
    (root / "db" / "schema.rb").write_text(RAILS_SCHEMA)
    (root / "app" / "models").mkdir(parents=True)
    (root / "app" / "models" / "patient.rb").write_text(RAILS_MODEL)
    (root / "openapi.json").write_text(json.dumps(OPENAPI))
    (root / "account.proto").write_text(PROTO)
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "schema.prisma").write_text("model Junk {\n  a String /// @pii email\n}")
    return root


def test_scan_reads_every_schema_kind(tmp_path):
    h = schema.scan(str(make_project(tmp_path)))
    assert h["user"] == {"contact": "email", "contact_addr": "email", "pager": "phone", "secretq": "pii"}
    assert h["customer"] == {"backup_contact": "email", "last_ip": "ipv4", "notes": "pii"}
    assert h["lead"] == {"reach_addr": "email"}
    assert h["patient"] == {"mrn": "pii", "ssn_last4": "pii", "diagnosis": "pii"}
    assert h["member"] == {"contact": "email", "backup": "phone"}
    assert h["account"] == {"recovery": "pii", "handle": "username"}
    assert "junk" not in h                                       # node_modules skipped


def test_hints_classify_columns_names_cannot(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "shop.json").write_text(json.dumps([{"model": "shop.customer", "pk": 1, "fields": {
        "backup_contact": "ops.lead@kestrel-mail.example.org", "last_ip": "81.2.69.160",
        "notes": "allergic to penicillin", "plan": "pro"}}]))
    core.set_hints(schema.scan(str(make_project(tmp_path / "app"))))
    try:
        known = KnownValues()
        report = seed(known, str(fixtures))
        kinds = {f.path: (f.kind, f.signal) for f in report.fields}
        assert kinds["backup_contact"] == ("email", "schema") and kinds["notes"] == ("pii", "schema")
        assert "plan" not in kinds
        assert known.canonical("ops.lead@kestrel-mail.example.org") and known.canonical("allergic to penicillin")
    finally:
        core.set_hints({})


def test_init_remembers_hints_for_later_seeds(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VEIL_VAULT_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("VEIL_TOKEN_SECRET", base64.b64encode(b"t" * 32).decode())
    proj = make_project(tmp_path / "proj")
    cli.main(["init", str(proj), "--dry-run"])
    assert "schema_hints" not in state.config()                  # dry run writes nothing
    cli.main(["init", str(proj), "--no-hooks", "--port", "1"])
    assert state.config()["schema_hints"]["customer"]["backup_contact"] == "email"
    core.set_hints({})
    state.load()                                                  # a later process (proxy, re-seeder)
    assert core.HINTS["customer"]["backup_contact"] == "email"
    core.set_hints({})
