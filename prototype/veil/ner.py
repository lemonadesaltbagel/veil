"""Optional NER layer for PII that no seeded source knows about (third parties
in tickets, free-text notes). Off by default; `pip install veil[ner]`.

Model: knowledgator/gliner-pii-edge-v1.0 (Apache-2.0), quantised ONNX, 46 MB,
~30 ms per 200 chars on a laptop CPU. Runs only on free text (messages, tool
results), never on system prompts/tool schemas. Results are cached by text
because agent histories are re-sent every turn (and caching keeps redaction
deterministic, which prompt caching needs).
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import OrderedDict

from .detect import Span

# Only labels that are safe in developer text. The model's `username` / `password`
# labels fire on identifiers, model ids and numbers (claude-opus-5-5, 14999989);
# usernames come from seeding and secrets from patterns instead.
LABELS = {"person": "name", "email": "email", "phone number": "phone", "street address": "address"}
# Harness-injected instructions (Claude Code system reminders): known values and
# patterns still apply there, NER does not.
SKIP_BLOCKS = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
MODEL_REPO = "knowledgator/gliner-pii-edge-v1.0"   # Apache-2.0
MODEL_FILES = ["gliner_config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
               "onnx/model_quint8.onnx"]
DEFAULT_PATH = os.environ.get("VEIL_NER_MODEL") or os.path.join(
    os.environ.get("VEIL_HOME", os.path.expanduser("~/.veil")), "models", "gliner-pii-edge-v1.0")


def fetch_model(dest: str = DEFAULT_PATH) -> str:
    """Download only the ~50 MB veil needs (the repo holds ~500 MB of variants)."""
    import httpx
    os.makedirs(os.path.join(dest, "onnx"), exist_ok=True)
    with httpx.Client(follow_redirects=True, timeout=300) as client:
        for name in MODEL_FILES:
            with client.stream("GET", f"https://huggingface.co/{MODEL_REPO}/resolve/main/{name}") as r:
                r.raise_for_status()
                with open(os.path.join(dest, name), "wb") as f:
                    for chunk in r.iter_bytes():
                        f.write(chunk)
    return dest
MIN_CHARS = 3
STOP = {"pw", "pwd", "pass", "user", "login", "admin", "mr", "mrs", "ms", "dr"}
# Products/orgs the model mistakes for people in developer text. Extend via VEIL_NER_ALLOW="A,B".
ALLOW = {"claude", "claude code", "anthropic", "openai", "chatgpt", "codex", "copilot", "github", "gitlab",
         "cursor", "gemini", "deepseek", "llama", "mistral", "python", "node", "docker", "postgres",
         "postgresql", "mysql", "mariadb", "redis", "mongodb", "sqlite", "linux", "windows", "macos", "veil"}
ALLOW |= {a.strip().lower() for a in os.environ.get("VEIL_NER_ALLOW", "").split(",") if a.strip()}


class GlinerDetector:
    def __init__(self, path: str = DEFAULT_PATH, threshold: float = 0.45, window: int = 1200,
                 overlap: int = 150, cache_size: int = 20_000):
        self.path, self.threshold, self.window, self.overlap = path, threshold, window, overlap
        self._model = None
        self._cache: OrderedDict[str, list[tuple[int, int, str, str]]] = OrderedDict()
        self._cache_size = cache_size

    def _load(self):
        if self._model is None:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(self.path, load_onnx_model=True, load_tokenizer=True,
                                                 onnx_model_file="onnx/model_quint8.onnx", local_files_only=True)
        return self._model

    def _windows(self, text: str):
        """Overlapping windows cut at whitespace; yields (offset, chunk)."""
        start = 0
        while start < len(text):
            end = min(len(text), start + self.window)
            if end < len(text):
                cut = text.rfind(" ", start + self.window - self.overlap, end)
                end = cut if cut > start else end
            yield start, text[start:end]
            if end >= len(text):
                break
            back = text.rfind(" ", end - self.overlap, end)
            start = back + 1 if back > start else end

    def find(self, text: str) -> list[Span]:
        if len(text.strip()) < MIN_CHARS or not re.search(r"[A-Za-z]", text):
            return []
        key = hashlib.sha256(text.encode()).hexdigest()
        hit = self._cache.get(key)
        if hit is None:
            model, found = self._load(), {}
            skip = [(m.start(), m.end()) for m in SKIP_BLOCKS.finditer(text)]
            for off, chunk in self._windows(text):
                for e in model.predict_entities(chunk, list(LABELS), threshold=self.threshold):
                    s, t = off + e["start"], off + e["end"]
                    value = text[s:t]
                    if (len(value) >= MIN_CHARS and value.lower().strip(".") not in STOP
                            and value.lower().strip(" .") not in ALLOW
                            and re.search(r"[^\W\d_]", value)
                            and not any(a <= s < b for a, b in skip)):
                        found[(s, t)] = (LABELS[e["label"]], value)
            hit = [(s, t, k, v) for (s, t), (k, v) in sorted(found.items())]
            self._cache[key] = hit
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        else:
            self._cache.move_to_end(key)
        return [Span(s, t, kind, value, None, priority=-1) for s, t, kind, value in hit]
