#!/usr/bin/env bash
# Download the public sample datasets used by tests, audits and evals into prototype/datasets/.
# They are not committed (third-party data, licenses not asserted); this script reproduces them.
#   Chinook       https://github.com/lerocha/chinook-database
#   sample_mflix  https://github.com/neelabalan/mongodb-sample-dataset (users, sessions, first 3000 comments)
#   user-database https://github.com/redis-developer/redis-datasets
#   ai4privacy    https://huggingface.co/datasets/ai4privacy/pii-masking-200k (first 1000 English rows)
set -euo pipefail
DS="$(cd "$(dirname "$0")/.." && pwd)/datasets"; mkdir -p "$DS/mflix"; cd "$DS"

CH=https://raw.githubusercontent.com/lerocha/chinook-database/master/ChinookDatabase/DataSources
curl -fsSL -o chinook.sqlite "https://github.com/lerocha/chinook-database/raw/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite"
curl -fsSL -o Chinook_PostgreSql.sql "$CH/Chinook_PostgreSql.sql"
curl -fsSL -o Chinook_MySql.sql "$CH/Chinook_MySql.sql"

MF=https://raw.githubusercontent.com/neelabalan/mongodb-sample-dataset/main/sample_mflix
curl -fsSL -o mflix/users.json "$MF/users.json"
curl -fsSL -o mflix/sessions.json "$MF/sessions.json"
curl -fsSL "$MF/comments.json" 2>/dev/null | head -n 3000 > mflix/comments.json || true  # first 3000 docs

curl -fsSL -o redis_users.redis \
  https://raw.githubusercontent.com/redis-developer/redis-datasets/master/user-database/import_users.redis

python3 - <<'PY'
import json, re, subprocess, uuid

# Redis: JSON sessions + a set of emails derived from the first 40 users
lines = open("redis_users.redis").read().splitlines()[:40]
with open("redis_extra.redis", "w") as out:
    for i, l in enumerate(lines):
        t = re.findall(r'"([^"]*)"', l)
        d = dict(zip(t[1::2], t[2::2]))
        blob = json.dumps({"user": {"id": t[0].split(":")[1], "email": d["email"],
                                    "name": f"{d['first_name']} {d['last_name']}"},
                           "csrf": "x" * 8, "ip": d["ip_address"]}).replace('"', '\\"')
        out.write(f'SET "sess:{uuid.UUID(int=i + 1).hex}" "{blob}"\n')
        if i < 25:
            out.write(f'SADD "newsletter:subscribers" "{d["email"]}"\n')

# ai4privacy: 1000 English rows with their labelled PII spans
rows = []
for off in range(0, 1000, 100):
    url = ("https://datasets-server.huggingface.co/rows?dataset=ai4privacy/pii-masking-200k"
           f"&config=default&split=train&offset={off}&length=100")
    data = json.loads(subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True).stdout)
    for r in data.get("rows", []):
        row = r["row"]
        if row["language"] == "en":
            mask = row["privacy_mask"]
            mask = json.loads(mask.replace("'", '"')) if isinstance(mask, str) else mask
            rows.append({"id": row["id"], "text": row["source_text"],
                         "pii": [{"value": m["value"], "label": m["label"]} for m in mask]})
json.dump(rows, open("ai4privacy_en_sample.json", "w"), ensure_ascii=False, indent=0)
print(f"datasets ready: chinook, mflix, redis ({len(lines)} sessions), ai4privacy ({len(rows)} rows)")
PY
