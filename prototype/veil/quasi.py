"""Quasi-identifiers: city, postal code, birth date, company, job title.

None of these names a person, but rare ones narrow it down to a few people, and
combinations single people out (ZIP + birth date + gender identifies most of a
population). Seeding records them with how many records share each value; only
values shared by fewer than QUASI_K records are considered.

    veil quasi warn     (default) log when rare ones reach the model; values unchanged
    veil quasi redact   pseudonymise rare ones too (city_ab12, dob_ab12, ...)
    veil quasi off

Warnings name kinds and counts, never values, and each value is reported once per
proxy run (the conversation history repeats it on every request).
"""

from __future__ import annotations

import threading

from .display import setting

MODES = ("warn", "redact", "off")


def mode(home: str) -> str:
    return setting(home, "quasi", "VEIL_QUASI", MODES, "warn")


class Monitor:
    def __init__(self):
        self.seen: set[str] = set()         # rare values reported
        self.seen_combos: set[str] = set()  # rare combinations of common values reported
        self._lock = threading.Lock()

    def check(self, known, texts) -> str | None:
        """A warning line for rare quasi-identifiers (or rare combinations of common ones)
        not reported before, or None."""
        texts = list(texts)
        hits = [s for t in texts for s in known.find_quasi(t)]
        combo_hits = [combo for t in texts for combo, _ in known.quasi_combos(t)]
        with self._lock:
            new = [s for s in hits if s.value not in self.seen]
            self.seen.update(s.value for s in new)
            keys = {"+".join(sorted(s.value for s in c)): c for c in combo_hits}
            new_combos = [c for k, c in keys.items() if k not in self.seen_combos]
            self.seen_combos.update(keys)
        if not new and not new_combos:
            return None
        if not new:
            kinds = sorted({"+".join(sorted(s.kind for s in c)) for c in new_combos})
            return (f"rare combinations of quasi-identifiers reached the model: {len(new_combos)} ({', '.join(kinds)})"
                    " (each value is common; together they point at fewer than 5 people; `veil quasi redact`)")
        kinds: dict[str, int] = {}
        for s in {s.value: s for s in new}.values():
            kinds[s.kind] = kinds.get(s.kind, 0) + 1
        per_person: dict[str, set] = {}
        for s in hits:  # combinations: this request as a whole
            if s.group:
                per_person.setdefault(s.group, set()).add(s.kind)
        combos = sum(1 for k in per_person.values() if len(k) >= 2)
        line = "quasi-identifiers reached the model: " + ", ".join(f"{k} x{n}" for k, n in sorted(kinds.items()))
        if combos:
            line += f"; {combos} person(s) with 2+ kinds together"
        if new_combos:
            line += f"; {len(new_combos)} rare combination(s) of common values"
        return line + " (rare values only; `veil quasi redact` pseudonymises them)"
