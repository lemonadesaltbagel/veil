"""Anthropic Messages API transforms.

Direction model ("the lens"):
  request  (machine -> model): every string in system/messages is redacted,
           including tool_use inputs that we rehydrated on an earlier turn, so
           the model's view of history is byte-stable (prompt caching works).
  response (model -> machine): tool_use inputs are rehydrated per *sink
           policy* so commands run against real data; assistant text is
           optionally rehydrated for display. Thinking blocks are never
           touched (they are signed, and only ever contain tokens).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .engine import Veil
from .stream import TextHold

# Byte-level dumps print data in escaped forms that bypass pseudonymisation
# (found with a real model: `sed -n l app.log`). They are replaced by a notice.
RAW_DUMP = re.compile(
    r"(?:^|[;&|(]\s*|\s)(?:od|xxd|hexdump|hd|strings|base64(?!\s+(?:-d|--decode)))\b"
    r"|\bcat\s+-\w*[vAeEtT]"
    r"|\bsed\b[^|;&]*?(?:\s|['\"])(?:-n\s+)?['\"]?(?:\d+(?:,\s*\d+)?|\$)?\s*l(?:\s*\d+)?['\"]?(?=\s|$|;)"
)
EGRESS = re.compile(
    r"\b(curl|wget|nc|ncat|telnet|ssh|scp|sftp|rsync|ftp|http|httpie|aws\s+s3|gsutil|git\s+push)\b"
)


CONTENT_FIELDS = {"new_string", "content", "new_source"}


PSEUDONYM_NOTICE = (
    "Privacy note: personal data in this session (names, emails, usernames, phones, addresses, "
    "home-directory names) has been replaced by consistent pseudonyms such as user_ab12, "
    "user_ab12@example.test, First_Ab12 Last_Ab12, Ab12 Example Street. They work like the real values "
    "when used whole and exactly (e.g. WHERE email = 'user_ab12@example.test', paths containing user_ab12). "
    "Fragments of a pseudonym (LIKE '%ab12%', partial greps, character slicing) will not match real data, "
    "so never search on parts of them. Do not try to recover the real values (byte dumps and escaped "
    "output are blocked); the developer sees real values in your answers automatically."
)


@dataclass
class Policy:
    display_real: bool = True  # rehydrate assistant text shown to the developer
    notice: bool = True  # tell the model pseudonyms are opaque (static text: cache-safe)
    full_tools: set[str] = field(default_factory=lambda: {"Bash", "Read", "Grep", "Glob", "LS"})
    preserve_tools: set[str] = field(default_factory=lambda: {"Edit", "MultiEdit", "Write", "NotebookEdit"})
    full_tool_prefixes: tuple[str, ...] = ()  # e.g. ("mcp__veil_db__",)

    def mode(self, tool: str, tool_input: dict) -> str:
        if tool == "Bash" and EGRESS.search(str(tool_input.get("command", ""))):
            return "none"  # never put real values into a network-capable command
        if tool in self.full_tools or tool.startswith(self.full_tool_prefixes):
            return "full"
        if tool in self.preserve_tools:
            return "preserve"
        return "none"  # unknown sinks (WebFetch, Agent, new tools) fail safe


_RX_META = set("\\.+*?()|[]{}^$#&-~")


def _rx_escape(s: str) -> str:
    """Escape for ripgrep's Rust regex (which rejects escaped spaces/letters)."""
    return "".join("\\" + c if c in _RX_META else c for c in s)


def _fragment_notice(veil: Veil, codes: list[str]) -> str:
    parts = []
    for code in dict.fromkeys(codes):
        toks = veil.code_tokens(code)[:4]
        parts.append(f"'{code}' (use one of: {', '.join(toks)})" if toks else f"'{code}'")
    msg = ("veil: " + "; ".join(parts) + " -- only part of a pseudonym. Pseudonyms match real data only "
           "when used whole and exactly. This command was not run; repeat it with a full pseudonym.")
    return "echo " + "'" + msg.replace("'", "") + "'"


def _texts(obj) -> str:
    """Every string in a tool input, NUL-separated. (Scanning json.dumps() output glued
    the `n` of an escaped newline onto a token after it, so the token went unseen.)"""
    out: list[str] = []

    def walk(o):
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(k)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(obj)
    return "\0".join(out)


def rehydrate_tool_input(veil: Veil, policy: Policy, tool: str, tool_input: dict) -> dict:
    mode = policy.mode(tool, tool_input)
    if mode == "full":
        frags = veil.fragments(_texts(tool_input))
        if frags and tool == "Grep" and isinstance(tool_input.get("pattern"), str):
            # "lines about person mz5z": expand the fragment to that person's real values
            pat, codes = tool_input["pattern"], veil.codes()
            for start, end, code in reversed(veil.fragments(pat)):
                pat = pat[:start] + "(?:" + "|".join(map(_rx_escape, codes[code])) + ")" + pat[end:]
            return {**veil.rehydrate_json({k: v for k, v in tool_input.items() if k != "pattern"}),
                    "pattern": veil.rehydrate(pat)}
        if frags and tool == "Bash":
            return {**tool_input, "command": _fragment_notice(veil, [c for *_, c in frags])}
        if tool == "Bash" and RAW_DUMP.search(str(tool_input.get("command", ""))):
            return {**tool_input, "command": "echo 'veil: byte-level dumps (sed l, od, xxd, hexdump, strings, "
                                             "cat -v, base64) are disabled: they bypass pseudonymisation. "
                                             "Read files normally; personal values are pseudonymised on purpose.'"}
        if tool == "Bash" and isinstance(tool_input.get("command"), str):
            # data -> code boundary: escape each real value for its quoting context
            from .shell import rehydrate_command
            rest = veil.rehydrate_json({k: v for k, v in tool_input.items() if k != "command"})
            return {**rest, "command": rehydrate_command(veil, tool_input["command"])}
        return veil.rehydrate_json(tool_input)
    if mode == "preserve":
        # Locators (paths, old_string) must be real or the edit misses its
        # target. Content fields rehydrate only tokens whose real value already
        # exists in the target file: edits keep existing data intact, but the
        # agent can never *introduce* real PII into source code or fixtures.
        out = {k: (v if k in CONTENT_FIELDS else veil.rehydrate_json(v)) for k, v in tool_input.items()}
        path = out.get("file_path") or out.get("notebook_path") or ""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                existing = f.read()
        except OSError:
            existing = ""
        allowed = {t for t in veil.tokens_in(_texts(tool_input))
                   if (veil.vault.value_for(t) or "\0") in existing}
        for k in CONTENT_FIELDS & out.keys():
            out[k] = veil.rehydrate_json(out[k], only=allowed)
        if isinstance(out.get("edits"), list):  # MultiEdit
            out["edits"] = [{**e, "old_string": veil.rehydrate(e.get("old_string", "")),
                             "new_string": veil.rehydrate(e.get("new_string", ""), only=allowed)}
                            for e in tool_input["edits"]]
        return out
    return tool_input


# -- requests --------------------------------------------------------------

def _redact_block(veil: Veil, block: Any, free_text: bool = False) -> Any:
    if not isinstance(block, dict):
        return veil.redact_json(block)
    t = block.get("type")
    if t in ("thinking", "redacted_thinking", "image"):
        return block
    if t == "text":
        return {**block, "text": veil.redact(block["text"], free_text=free_text)}
    if t == "tool_use":
        return {**block, "input": veil.redact_json(block.get("input", {}))}
    if t == "tool_result":
        content = block.get("content")
        if isinstance(content, str):
            content = veil.redact(content, free_text=True)
        elif isinstance(content, list):
            content = [_redact_block(veil, b, free_text=True) for b in content]
        return {**block, "content": content}
    # documents, search results, unknown future block types: redact all strings
    return veil.redact_json(block)


# Top-level fields that are pure configuration; everything else is redacted.
# Default-deny matters: Claude Code 2.1.285 sends `safeguards[].classifier_context`
# (home_dir, user_identity, cwd, git state) next to system/messages.
CONFIG_FIELDS = {"model", "max_tokens", "stream", "temperature", "top_p", "top_k", "stop_sequences",
                 "thinking", "tool_choice", "output_config", "context_management", "service_tier",
                 "anthropic_version", "anthropic_beta"}  # last two: Bedrock/Vertex body fields


def redact_request(veil: Veil, body: dict, notice: bool = False) -> dict:
    out = {}
    for key, value in body.items():
        if key in CONFIG_FIELDS:
            out[key] = value
        elif key == "system" and isinstance(value, list):
            out[key] = [_redact_block(veil, b) for b in value]
        elif key == "messages" and isinstance(value, list):
            out[key] = [{**msg, "content": veil.redact(msg["content"], free_text=True)
                         if isinstance(msg.get("content"), str)
                         else [_redact_block(veil, b, free_text=True) for b in msg.get("content") or []]}
                        for msg in value]
        else:  # system as str, tools, metadata, safeguards, unknown future fields
            out[key] = veil.redact_json(value)
    if notice and out.get("messages") and out.get("tools"):  # agent requests only
        system = out.get("system")
        if isinstance(system, list):
            out["system"] = system + [{"type": "text", "text": PSEUDONYM_NOTICE}]
        else:
            out["system"] = (system + "\n\n" if system else "") + PSEUDONYM_NOTICE
    return out


# -- non-streaming responses -----------------------------------------------

def rehydrate_response(veil: Veil, policy: Policy, body: dict) -> dict:
    content = []
    for block in body.get("content", []):
        if block.get("type") == "text" and policy.display_real:
            block = {**block, "text": veil.rehydrate(block["text"])}
        elif block.get("type") == "tool_use":
            block = {**block, "input": rehydrate_tool_input(veil, policy, block["name"], block.get("input", {}))}
        content.append(block)
    return {**body, "content": content}


# -- streaming responses ---------------------------------------------------

class StreamRewriter:
    """Rewrites SSE events from /v1/messages with stream=true.

    * text_delta: rehydrated incrementally. A token may be split across
      deltas, so we hold back up to max-token-length chars until it is safe.
    * input_json_delta: buffered until content_block_stop, then the whole
      input is rehydrated by policy and emitted as one delta.
    * everything else (pings, thinking, signatures, usage) passes through
      untouched and immediately, so idle watchdogs never fire.
    """

    def __init__(self, veil: Veil, policy: Policy):
        self.veil, self.policy = veil, policy
        self.blocks: dict[int, dict] = {}

    def feed(self, event: str, data: dict) -> list[tuple[str, dict]]:
        t = data.get("type", event)
        if t == "content_block_start":
            cb = data["content_block"]
            st = {"type": cb.get("type"), "hold": TextHold(self.veil), "json": "", "name": cb.get("name")}
            self.blocks[data["index"]] = st
            if st["type"] == "text" and cb.get("text"):
                text, cb = cb["text"], {**cb, "text": ""}
                return [(event, {**data, "content_block": cb})] + self._text(data["index"], st["hold"].feed(text))
            return [(event, data)]
        if t == "content_block_delta":
            idx, delta = data["index"], data["delta"]
            st = self.blocks.get(idx)
            if st and st["type"] == "text" and delta.get("type") == "text_delta" and self.policy.display_real:
                return self._text(idx, st["hold"].feed(delta["text"]))
            if st and delta.get("type") == "input_json_delta" and st["type"] == "tool_use":
                st["json"] += delta.get("partial_json", "")
                return []
            return [(event, data)]
        if t == "content_block_stop":
            idx = data["index"]
            st = self.blocks.pop(idx, None)
            out: list[tuple[str, dict]] = []
            if st and st["type"] == "text":
                out = self._text(idx, st["hold"].flush())
            elif st and st["type"] == "tool_use":
                try:
                    tool_input = json.loads(st["json"]) if st["json"].strip() else {}
                except json.JSONDecodeError:
                    tool_input = None
                if tool_input is None:  # malformed: pass through verbatim
                    partial = st["json"]
                else:
                    partial = json.dumps(
                        rehydrate_tool_input(self.veil, self.policy, st["name"], tool_input),
                        ensure_ascii=False,
                    )
                if partial:
                    out.append(("content_block_delta", {
                        "type": "content_block_delta", "index": idx,
                        "delta": {"type": "input_json_delta", "partial_json": partial},
                    }))
            return out + [(event, data)]
        return [(event, data)]

    @staticmethod
    def _text(idx: int, text: str) -> list[tuple[str, dict]]:
        if not text:
            return []
        return [("content_block_delta", {
            "type": "content_block_delta", "index": idx,
            "delta": {"type": "text_delta", "text": text},
        })]
