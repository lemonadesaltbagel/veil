"""How much labelled PII survives redaction? (ai4privacy/pii-masking-200k sample)

Two modes:
  patterns  - no seeding: only veil's regex layer (what you get for PII that is
              NOT in your data sources, e.g. free text from a third party)
  seeded    - person/contact values pre-loaded as known values, simulating
              "this person exists in your users table"

A value "leaks" if it still appears verbatim in the redacted text.

    uv run python scripts/eval_ai4privacy.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from veil.detect import KnownValues  # noqa: E402
from veil.engine import Veil  # noqa: E402
from veil.vault import Vault  # noqa: E402

DATA = os.path.join(ROOT, "datasets", "ai4privacy_en_sample.json")
OUT = os.path.join(ROOT, "captures", "ai4privacy")
SEEDABLE = {"FIRSTNAME": "first_name", "LASTNAME": "last_name", "MIDDLENAME": "name", "EMAIL": "email",
            "USERNAME": "username", "PHONENUMBER": "phone", "STREET": "address", "IPV4": "ipv4"}


def run(rows, seeded: bool, ner=None):
    known = KnownValues()
    if seeded:
        for r in rows:
            for p in r["pii"]:
                if p["label"] in SEEDABLE:
                    known.add(p["value"], SEEDABLE[p["label"]], f"row:{r['id']}")
    veil = Veil(Vault(":memory:", b"eval"), known, ner=ner)
    total, leaked, examples = Counter(), Counter(), {}
    for r in rows:
        out = veil.redact(r["text"], free_text=ner is not None)
        for p in r["pii"]:
            total[p["label"]] += 1
            if p["value"] in out:
                leaked[p["label"]] += 1
                examples.setdefault(p["label"], []).append(p["value"])
    return total, leaked, examples


def main() -> int:
    rows = json.load(open(DATA))
    os.makedirs(OUT, exist_ok=True)
    t, lp, ex = run(rows, seeded=False)
    _, ls, exs = run(rows, seeded=True)
    ner = None
    if "--no-ner" not in sys.argv:
        try:
            from veil.ner import GlinerDetector
            ner = GlinerDetector()
            import time
            t0 = time.time()
            _, ln, exn = run(rows, seeded=False, ner=ner)
            ner_secs = time.time() - t0
        except ImportError:
            ner = None
    lines = [f"# Free-text PII surviving redaction — {len(rows)} ai4privacy rows", "",
             "Leak rate = share of labelled values still present verbatim after veil.", "",
             "| label | count | patterns only | patterns + NER | seeded from your data | example leak (patterns) |",
             "|---|---|---|---|---|---|"]
    for label, n in t.most_common():
        mark = " *" if label in SEEDABLE else ""
        e = (ex.get(label) or [""])[0].replace("|", "\\|").replace("\n", " ")[:40]
        nr = f"{ln[label] / n:.0%}" if ner else "n/a"
        lines.append(f"| {label}{mark} | {n} | {lp[label] / n:.0%} | {nr} | {ls[label] / n:.0%} | `{e}` |")
    lines += ["", "\\* person/contact label (pre-loaded as a known value in the seeded run).",
              "NER = knowledgator/gliner-pii-edge-v1.0 (quantised ONNX, 46 MB), threshold 0.45."]
    tot = sum(t.values())
    seedable = sum(t[k] for k in SEEDABLE)
    summary = {"rows": len(rows), "labelled_values": tot,
               "person_contact_leak": {"patterns": round(sum(lp[k] for k in SEEDABLE) / seedable, 3),
                                       "patterns+ner": round(sum(ln[k] for k in SEEDABLE) / seedable, 3) if ner else None,
                                       "seeded": round(sum(ls[k] for k in SEEDABLE) / seedable, 3)},
               "all_labels_leak": {"patterns": round(sum(lp.values()) / tot, 3),
                                   "patterns+ner": round(sum(ln.values()) / tot, 3) if ner else None,
                                   "seeded": round(sum(ls.values()) / tot, 3)},
               "ner_seconds": round(ner_secs, 1) if ner else None,
               "ner_misses_examples": {k: exn[k][:4] for k in SEEDABLE if ner and exn.get(k)}}
    lines.insert(2, "```json\n" + json.dumps(summary, indent=2, ensure_ascii=False) + "\n```\n")
    with open(os.path.join(OUT, "REPORT.md"), "w") as f:
        f.write("\n".join(lines))
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\n".join(lines[-len(t) - 3:-3][:24]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
