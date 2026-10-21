"""The anchored Aho-Corasick matcher must behave exactly like the regex it replaced:
leftmost-longest, non-overlapping, identifier boundaries."""

import random
import re

from veil.engine import Veil
from veil.match import Matcher, Prefixes
from veil.vault import Vault

WORD = r"A-Za-z0-9_"


def _regex_find(needles, text, bounded):
    alt = "|".join(map(re.escape, sorted(set(needles), key=len, reverse=True)))
    pat = re.compile(f"(?<![{WORD}])(?:{alt})(?![{WORD}])" if bounded else f"(?:{alt})")
    return [(m.start(), m.end(), m.group()) for m in pat.finditer(text)]


def test_matches_regex_semantics_on_random_input():
    rng = random.Random(3)
    alphabet = "ab_ .@-é"
    for trial in range(300):
        # short alphabets force shared anchors, overlaps and needles shorter than an anchor
        needles = {"".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12))) for _ in range(rng.randint(1, 25))}
        needles = {n for n in needles if n.strip()}
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        for bounded in (True, False):
            want = _regex_find(needles, text, bounded)
            # regex alternation is leftmost-first-listed (longest); same as leftmost-longest
            assert Matcher(needles, bounded).find(text) == want, (needles, text, bounded)


def test_extended_grows_without_disturbing_the_old_matcher():
    m = Matcher(["First_Ab12", "user_k3f9"])
    same = m.extended(["First_Cd34"])  # shares the anchor "First_": no new automaton
    assert same is m and [h[2] for h in m.find("First_Cd34 x")] == ["First_Cd34"]
    grown = m.extended(["Zz99 Example Street"])  # new anchor: a new automaton to swap in
    assert grown is not m
    assert [h[2] for h in grown.find("at Zz99 Example Street, First_Ab12")] == ["Zz99 Example Street", "First_Ab12"]
    assert [h[2] for h in m.find("First_Ab12")] == ["First_Ab12"]  # old one still works


def test_prefixes_are_proper_and_reversible():
    p = Prefixes(["Leonie Köhler", "leonekohler@surfeu.de"])
    assert p.owner("Leonie Kö") == "Leonie Köhler"
    assert p.owner("Leonie Köhler") is None  # whole value: not a truncation
    assert p.owner("Leonie X") is None
    t = Prefixes(["leonekohler@surfeu.de"], reverse=True)
    assert t.owner("hler@surfeu.de") == "leonekohler@surfeu.de"


def test_token_pattern_is_regex_compatible_and_incremental():
    veil = Veil(Vault(":memory:", b"t"))
    toks = [veil.vault.token_for("email", f"person{i}@corp.example.com", f"g{i}") for i in range(50)]
    toks += [veil.vault.token_for("name", f"Person Number{i}", f"g{i}") for i in range(50)]
    text = " | ".join(toks) + " x" + toks[0] + " " + toks[3] + "_suffix"
    pattern = veil.token_pattern()
    want = _regex_find(toks, text, bounded=True)
    assert [(m.start(), m.end(), m.group()) for m in pattern.finditer(text)] == want
    assert pattern.findall(text) == [w[2] for w in want]
    assert veil.rehydrate(toks[5]) == "person5@corp.example.com"
    new = veil.vault.token_for("address", "1 Brand New Road")
    assert veil.rehydrate(f"lives at {new}.") == "lives at 1 Brand New Road."
