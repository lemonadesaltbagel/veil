# Veil — Seeding from databases and other data stores

*2026-10-19. Research (web + docs) and implementation status. Code: `prototype/veil/sources/`.*

Seeding = learning the real PII values from the developer's own data, so they can be pseudonymised
everywhere they later appear (logs, fixtures, query output, free text). It is veil's strongest
signal: on 1,000 labelled free-text rows, name/contact leak rate is **80% with patterns only, 17.6%
with patterns + NER, 1.8% when the people are seeded** (`captures/ai4privacy/REPORT.md`).

## Implemented and tested

| Source | Enumeration | Nested data | Grouping (one person = one code) | Test data |
|---|---|---|---|---|
| SQLite | `PRAGMA table_info / index_list / foreign_key_list` | JSON text | PK; unique FK or identity-less FK → person | Chinook |
| PostgreSQL | `pg_attribute` (tables + partition parents, no views/matviews/partitions), comments, `pg_seclabels` | `jsonb`/`json` paths, `text[]`, `citext`, `inet` | PK; FKs from `pg_constraint` + unique indexes | Chinook + `pg_app_schema.sql` (JSONB profiles, arrays, tenant schema, comment-only and value-only columns) |
| MySQL / MariaDB | `information_schema.COLUMNS` (+ `COLUMN_COMMENT`, `COLUMN_KEY`), `KEY_COLUMN_USAGE` | `JSON` (incl. MariaDB's LONGTEXT JSON), generated columns | same | Chinook + `mysql_app_schema.sql` |
| MongoDB | `$sample` 300 docs per collection → flattened paths | sub-docs, arrays (`phones[].number`), **JWT payloads** (`jwt.$jwt.identity.email`) | `_id`; `*_id` fields only if values look like ids | sample_mflix users/sessions/comments (via mongomock; live server needs `brew trust mongodb/brew`) |
| Redis | `SCAN` + `TYPE`; containers = key patterns (`user:42` → `user:{id}`) | hashes, JSON strings, sets/lists | key; sessions/sets join people by value | redis-developer user-database (6k hashes) + JSON sessions + a set |
| Fixture files | dirs/files: JSON, JSONL, CSV, Django fixtures, mongoexport (extended JSON, JSONL-in-.json) | yes | `id`/`pk`/`_id` | tests |
| Environment | OS user, home dir name, git author | — | `env:developer` | — |
| SQL Server | `sys.columns`, `MS_Description`, **`sys.sensitivity_classifications`** (information type → kind), **`sys.masked_columns`** (`email()` → email) | text columns; birth dates | PK; FKs from `sys.foreign_key_columns` | fake DB-API connection serving the catalog queries (no server here) |
| Elasticsearch / OpenSearch | `_mapping` (nested objects as paths), field `meta` (`{"pii": "email"}`), random-score sampling, scroll | objects | `customer_id` / `user_id` when present (denormalised events), else `_id` | fake REST server shaped like Kibana's ecommerce sample |
| Code (no data) | Prisma (`/// @pii`, `/// @encrypted`, `@map`), Django (`EmailField`, `GenericIPAddressField`, `PhoneNumberField`), Rails (`encrypts`, `filter_attributes`, `schema.rb` comments), SQLAlchemy (`EmailType`…), OpenAPI (`format: email`, `x-pii`), protobuf (`debug_redact`) | — | hints applied to every source whose table/collection matches the model | synthetic project |

`veil seed postgresql://… mysql://… redis://… mongodb://… app.db fixtures/` seeds them all; one run over
the four local test stores learned 28,914 values.

### Classification signals (strongest first)
1. **Native tags**: column comments `pii:<kind>`; pg_anonymizer `SECURITY LABEL FOR anon … MASKED WITH FUNCTION anon.fake_email()` → kind from the function name.
2. **Names / paths**: veil rules on the field path (`profile.name.given` → first_name, `phones[].number` → phone, plural `emails[]` → email), then the vendored **pg_anonymizer identifier dictionary** (PostgreSQL License) mapped selectively: contact categories yes, French/other spellings yes (`courriel`, `prenom`, `portable`), **opaque ids no** (`id`, `uid`, `client_id` — pseudonymising ids breaks code), dates no.
3. **Value sampling**: ≥80% of ≥5 sampled values look like emails (Unicode local parts allowed), phones (must have `+` or separators — bare digit runs are ids/timestamps) or public IPs. The only signal for `c1`, `contact`, `value`.
4. **Context**: a bare `name` is a person only in a person-like container (users, customers, leads…) or next to an email/username in the same record.

### Grouping rules
- Follow a foreign key to a person table only if it is **unique** (1:1 extension: `accounts.customer_id`)
  or the referring table has **no identity of its own** (child data: `invoice.customer_id` → billing
  address). Never for associations: `customer.support_rep_id` is a different person.
- Records with no FK join a known person when an **email or username** matches (denormalised copies,
  other stores: Mongo comments, Redis sessions). Never on names (homonyms) or addresses (households).
- Persons are seeded before referrers; first source wins for a repeated value.
- Extra values of the same kind for one person get numbered variants of the same code:
  `user_ayp8`, `user_ayp8_2`, `user_ayp8+2@example.test` (plus-addressing keeps it a valid email).

### Bugs the real data found (all fixed, all with regression tests)
- `ip_address` matched the street-address rule; `last_login` Unix timestamps were classified as phones by value sampling (would have pseudonymised 6,000 timestamps).
- Non-ASCII email local parts (`luís.gonçalves@…`, 25% of one column) failed the ASCII-only email regex.
- mflix `sessions.user_id` holds an **email**, not an id — the reference heuristic hid it.
- mongoexport files are JSON Lines named `.json` with `{"$oid": …}` keys — silently skipped before.
- A second email/username of the same person got an unrelated code (looked like a second person).

## Research: other database families (not implemented yet)

| Family | How to enumerate | Where PII hides | Native classification to reuse |
|---|---|---|---|
| SQL Server | `sys.columns`, `sys.extended_properties` (`MS_Description`) | XML columns, temporal history tables | `sys.sensitivity_classifications` (2019+), `sys.masked_columns` (`email()` mask ⇒ email) |
| Oracle | `ALL_TAB_COLUMNS`, `ALL_COL_COMMENTS` | `JSON`/CLOB `IS JSON` | `REDACTION_COLUMNS`, Data Safe sensitive columns |
| DynamoDB | `DescribeTable` (keys only) + `Scan Limit` | **inside keys**: `PK=USER#alice@x.com`, GSI keys | — (split key segments on `#`) |
| Firestore / CouchDB | collection ids, `_all_docs` | doc ids like `user:email` | — |
| Elasticsearch / OpenSearch | `_mapping` / `_field_caps`, `_search` sampling | denormalised per-event docs (`customer_full_name`); group by `customer_id`, not `_id` | field `meta` tags |
| Snowflake | `INFORMATION_SCHEMA.COLUMNS`, `LATERAL FLATTEN` on VARIANT | semi-structured | `SEMANTIC_CATEGORY` / `PRIVACY_CATEGORY` tags, `SYSTEM$CLASSIFY` |
| BigQuery | `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` (STRUCT/ARRAY paths) | nested records | policy tags (same view), DLP column data profiles |
| Redshift / ClickHouse | `SVV_COLUMNS` / `system.columns` | `SUPER` / `JSON`, `Map`, `Nested` | comments; FKs not enforced → name-based joins |
| Neo4j / InfluxDB | `db.schema.nodeTypeProperties()` / `SHOW TAG KEYS` | node properties / tags (`user`, `client_ip`) | — |
| Code (no DB) | Prisma, Django, Rails `schema.rb`, SQLAlchemy, Mongoose, GraphQL, OpenAPI, protobuf | names + types | Rails `encrypts`/`filter_attributes`, Lockbox, `prisma-field-encryption` `/// @encrypted`, protobuf `debug_redact`, OpenAPI `format: email`, Django `EmailField` |

Done since: SQL Server, schema-from-code, Elasticsearch (2026-10-21). Next: DynamoDB (key-segment
splitting) → warehouses (Snowflake/BigQuery native tags).

### Quasi-identifiers and direct identifiers (2026-10-21)
Person records also yield birth dates, postal codes, cities, companies and job titles (`qi:*`), each
with the number of records sharing it. Only rare values (< 5 records) are reported or pseudonymised
(`veil quasi`). Columns for SSNs, passports, national or tax IDs, licences and IBANs are `id_number`
and always pseudonymised.

### Classification fixes from new data shapes
- **camelCase columns** are classified via snake_case. `ShipAddress` used to be excluded as an IP
  address (`Sh·ip·Address`).
- **`pii:ipv4` comment tags** lost their digit (`[a-z_]+`), so the kind was dropped.
- **Person-prefixed names** are recognized: `customer_full_name`, `billing_first_name`,
  `ContactName`. `product_name` still isn't.
- **`city_name`** is recognized as a city, and a bare **`user`** handle next to an email is a
  username.
- **A column tagged plain `pii`** with no other recognisable kind used to be dropped; it is now
  seeded as an opaque value.

### Pitfalls to keep in mind
Partition children and views double-count; generated columns are copies; audit/history and
soft-deleted rows still leak into logs (seed them); hashed/encrypted columns (bcrypt `$2b$`, hex-64)
are useless as seeds; sample randomly (`TABLESAMPLE`, `$sample`) rather than `LIMIT` (biased to old
rows); never select non-text columns; connect read-only with a statement timeout.

### Sample datasets used / recommended
Chinook (all SQL dialects + SQLite), Pagila (partitions, matviews, JSONB variant), Northwind,
AdventureWorks (SQL Server, XML PII), MongoDB sample_mflix + sample_analytics, redis-developer
user-database, Kibana ecommerce sample (Elasticsearch).
