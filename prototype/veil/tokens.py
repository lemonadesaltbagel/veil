"""Deterministic, format-aware pseudonym generation.

Tokens are derived with HMAC-SHA256(secret, kind || value), so:
  * the same real value always maps to the same token (stable prompt-cache
    prefixes, coherent multi-turn reasoning, shareable bug reports when a team
    shares the secret);
  * the provider cannot brute-force a token back to e.g. an email address
    without the secret (unlike a plain hash).
Values that belong to the same record (a "group", e.g. users row 42) share one
code, so the model sees `user_k3f9`, `user_k3f9@example.test` and `User K3f9`
and can still reason that they are the same person.
"""

from __future__ import annotations

import hashlib
import hmac

# No 0/o/1/l: tokens are read by humans and models, avoid look-alikes.
ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
RESERVED_EMAIL_DOMAIN = "example.test"  # RFC 2606/6761 reserved, never routable


def code(secret: bytes, material: str, length: int = 4) -> str:
    digest = hmac.new(secret, material.encode(), hashlib.sha256).digest()
    n = int.from_bytes(digest, "big")
    out = []
    for _ in range(length):
        n, r = divmod(n, len(ALPHABET))
        out.append(ALPHABET[r])
    return "".join(out)


def _digits(secret: bytes, material: str, count: int) -> str:
    digest = hmac.new(secret, ("digits\x00" + material).encode(), hashlib.sha256).digest()
    return "".join(str(b % 10) for b in digest[:count])


def render(kind: str, c: str, secret: bytes, n: int = 1) -> str:
    """Render a token of the given kind from code `c`.

    Formats keep the value *shaped* like the original so that validators,
    parsers and tests written by the agent still behave sensibly. Fixed-format
    kinds (phone, ipv4) have small spaces; the vault retries on collision.
    """
    v = "" if n == 1 else str(n)  # n-th value of this kind for the same person
    if kind == "username":
        return f"user_{c}" + (f"_{v}" if v else "")
    if kind == "email":  # plus-addressing keeps it a valid email of the same person
        return f"user_{c}" + (f"+{v}" if v else "") + f"@{RESERVED_EMAIL_DOMAIN}"
    if kind == "name":  # composes with the parts: "First_Ab12 Last_Ab12" == first + " " + last
        sfx = f"_{v}" if v else ""
        return f"First_{c.capitalize()}{sfx} Last_{c.capitalize()}{sfx}"
    if kind == "first_name":
        return f"First_{c.capitalize()}" + (f"_{v}" if v else "")
    if kind == "last_name":
        return f"Last_{c.capitalize()}" + (f"_{v}" if v else "")
    if kind == "address":
        return f"{c.capitalize()} Example Street" + (f" {v}" if v else "")
    if n > 1 and kind in ("phone", "ipv4"):
        c = f"{c}#{n}"  # fixed formats: a different number/address, derived from the same code
    if kind == "phone":
        # 555-0100..0199 is reserved for fiction in NANP.
        d = _digits(secret, c, 5)
        return f"+1-{200 + int(d[:3]) % 800}-555-01{d[3:]}"
    if kind == "ipv4":
        # RFC 5737 documentation ranges, never routable.
        n = int(_digits(secret, c, 4)) % 762
        net = ("192.0.2", "198.51.100", "203.0.113")[n // 254]
        return f"{net}.{n % 254 + 1}"
    return f"{kind}_{c}" + (f"_{v}" if v else "")
