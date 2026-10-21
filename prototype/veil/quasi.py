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
        self.seen: set[str] = set()
        self._lock = threading.Lock()

    def check(self, known, texts) -> str | None:
        """A warning line for rare quasi-identifiers not reported before, or None."""
        hits = [s for t in texts for s in known.find_quasi(t)]
        with self._lock:
            new = [s for s in hits if s.value not in self.seen]
            self.seen.update(s.value for s in new)
        if not new:
            return None
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
        return line + " (rare values only; `veil quasi redact` pseudonymises them)"
