"""OpenAI Responses API transforms (Codex CLI; any client of /v1/responses).

Request items: message (input_text/output_text parts), function_call (JSON
arguments string), function_call_output, custom_tool_call(+_output),
local_shell_call, reasoning (encrypted: never touched). `instructions` and every
unknown field are redacted (default-deny); config fields pass.

Streamed responses are rewritten so deltas, `*.done` events, `output_item.done`
and the final `response.completed` all agree: text is rehydrated incrementally
(hold-back), function-call arguments are buffered and rehydrated once per item
by sink policy (exec_command -> Bash policy; write_stdin -> no real values,
since it types into a possibly-shell session; apply_patch -> preserve).
"""

from __future__ import annotations

import json
import re
from typing import Any

from .anthropic import PSEUDONYM_NOTICE, Policy, rehydrate_tool_input
from .engine import Veil
from .openai import _redact_arguments, _redact_content, rehydrate_args
from .stream import TextHold

CONFIG = {"model", "tool_choice", "parallel_tool_calls", "reasoning", "store", "stream", "include",
          "prompt_cache_key", "max_output_tokens", "temperature", "top_p", "truncation", "service_tier",
          "previous_response_id", "text", "background", "max_tool_calls", "stream_options"}
NO_REAL = {"write_stdin"}  # keystrokes into a running (maybe shell) session: fail safe
PATCH_FILES = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$", re.M)


def _redact_item(veil: Veil, it: Any) -> Any:
    if not isinstance(it, dict):
        return veil.redact_json(it)
    t = it.get("type")
    if t == "reasoning":
        return it  # encrypted / model-written: like signed thinking, leave untouched
    if t == "message" or (t is None and "role" in it):
        role = it.get("role")
        return {**it, "content": _redact_content(veil, it.get("content"), free_text=role in ("user", "assistant"))}
    if t == "function_call":
        return {**it, "arguments": _redact_arguments(veil, it.get("arguments", ""))}
    if t in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
        out = it.get("output")
        out = veil.redact(out, free_text=True) if isinstance(out, str) else _redact_content(veil, out, True)
        return {**it, "output": out}
    if t == "custom_tool_call":
        return {**it, "input": veil.redact(it.get("input", ""))}
    return veil.redact_json(it)  # local_shell_call, web_search_call, unknown future items


def redact_responses_request(veil: Veil, body: dict, notice: bool = False) -> dict:
    out = {}
    for key, value in body.items():
        if key in CONFIG:
            out[key] = value
        elif key == "input":
            out[key] = veil.redact(value, free_text=True) if isinstance(value, str) else \
                [_redact_item(veil, it) for it in value]
        else:  # instructions, tools, client_metadata, unknown future fields
            out[key] = veil.redact_json(value)
    if notice and out.get("tools") and isinstance(out.get("input"), list):
        items, i = out["input"], 0
        while i < len(items) and isinstance(items[i], dict) and items[i].get("role") in ("developer", "system"):
            i += 1  # stable prefix -> prompt caching keeps working
        out["input"] = items[:i] + [{"type": "message", "role": "developer",
                                     "content": [{"type": "input_text", "text": PSEUDONYM_NOTICE}]}] + items[i:]
    return out


# -- responses ----------------------------------------------------------------------

def _patch_input(veil: Veil, policy: Policy, text: str) -> str:
    """apply_patch freeform input: preserve semantics over the files it touches.
    Header paths are always made real (or the patch misses its file); other tokens
    only if their real value already exists in a touched file (no new PII in code)."""
    tokens = veil.tokens_in(text)
    allowed = set()
    for path in PATCH_FILES.findall(text):
        allowed |= veil.tokens_in(path)
        try:
            existing = open(veil.rehydrate(path.strip()), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        allowed |= {t for t in tokens if (veil.vault.value_for(t) or "\0") in existing}
    return veil.rehydrate(text, only=allowed)


class ItemRehydrator:
    """Rehydrates output items once per item id (so every event carrying an item agrees)."""

    def __init__(self, veil: Veil, policy: Policy):
        self.veil, self.policy = veil, policy
        self.args: dict[str, str] = {}

    def arguments(self, item_id: str, name: str, raw: str) -> str:
        if item_id not in self.args:
            self.args[item_id] = raw if name in NO_REAL else rehydrate_args(self.veil, self.policy, name, raw)
        return self.args[item_id]

    def item(self, it: dict) -> dict:
        t = it.get("type")
        if t == "message" and self.policy.display_real:
            return {**it, "content": [{**p, "text": self.veil.rehydrate(p["text"])} if isinstance(p, dict)
                                      and isinstance(p.get("text"), str) else p for p in it.get("content", [])]}
        if t == "function_call":
            key = it.get("id") or it.get("call_id") or ""
            return {**it, "arguments": self.arguments(key, it.get("name", ""), it.get("arguments", ""))}
        if t == "custom_tool_call" and it.get("name") == "apply_patch":
            return {**it, "input": _patch_input(self.veil, self.policy, it.get("input", ""))}
        if t == "local_shell_call":
            action = it.get("action") or {}
            cmd = action.get("command")
            if isinstance(cmd, list):
                fixed = json.loads(rehydrate_args(self.veil, self.policy, "shell", json.dumps({"command": cmd})))
                return {**it, "action": {**action, "command": fixed["command"]}}
        return it  # reasoning, web_search_call, unknown: untouched


def rehydrate_responses_body(veil: Veil, policy: Policy, body: dict) -> dict:
    ir = ItemRehydrator(veil, policy)
    return {**body, "output": [ir.item(it) for it in body.get("output", [])]}


class ResponsesStreamRewriter:
    def __init__(self, veil: Veil, policy: Policy):
        self.veil, self.policy = veil, policy
        self.items = ItemRehydrator(veil, policy)
        self.text: dict[tuple, TextHold] = {}
        self.names: dict[str, str] = {}
        self.raw_args: dict[str, str] = {}
        self.view: dict = {"content": [], "usage": {}, "model": None, "stop_reason": None}

    def feed(self, ev: dict) -> list[dict]:
        t = ev.get("type", "")
        if t == "response.output_item.added":
            it = ev.get("item") or {}
            if it.get("type") == "function_call":
                self.names[it.get("id", "")] = it.get("name", "")
            return [ev]
        if t == "response.output_text.delta":
            key = (ev.get("item_id"), ev.get("content_index", 0))
            self._view_text(ev.get("delta", ""))
            if not self.policy.display_real:
                return [ev]
            out = self.text.setdefault(key, TextHold(self.veil)).feed(ev.get("delta", ""))
            return [{**ev, "delta": out}] if out else []
        if t == "response.output_text.done":
            key = (ev.get("item_id"), ev.get("content_index", 0))
            tail = self.text.pop(key).flush() if key in self.text else ""
            done = {**ev, "text": self.veil.rehydrate(ev.get("text", ""))} if self.policy.display_real else ev
            return ([{**ev, "type": "response.output_text.delta", "delta": tail}] if tail else []) + [done]
        if t == "response.content_part.done" and self.policy.display_real:
            part = ev.get("part") or {}
            if isinstance(part.get("text"), str):
                return [{**ev, "part": {**part, "text": self.veil.rehydrate(part["text"])}}]
            return [ev]
        if t == "response.function_call_arguments.delta":
            self.raw_args[ev.get("item_id", "")] = self.raw_args.get(ev.get("item_id", ""), "") + ev.get("delta", "")
            return []  # emitted whole at .done, after policy
        if t == "response.function_call_arguments.done":
            iid = ev.get("item_id", "")
            raw = ev.get("arguments", self.raw_args.get(iid, ""))
            args = self.items.arguments(iid, self.names.get(iid, ""), raw)
            self.view["content"].append({"type": "tool_use", "name": self.names.get(iid, ""), "input": _loads(raw)})
            return [{"type": "response.function_call_arguments.delta", "item_id": iid,
                     "output_index": ev.get("output_index"), "delta": args},
                    {**ev, "arguments": args}]
        if t == "response.output_item.done":
            return [{**ev, "item": self.items.item(ev.get("item") or {})}]
        if t in ("response.completed", "response.done", "response.incomplete", "response.failed"):
            resp = ev.get("response") or {}
            self.view["usage"] = resp.get("usage") or {}
            self.view["model"] = resp.get("model")
            self.view["stop_reason"] = resp.get("status")
            return [{**ev, "response": {**resp, "output": [self.items.item(i) for i in resp.get("output", [])]}}]
        return [ev]  # created, in_progress, reasoning events, content_part.added, errors

    def _view_text(self, d: str) -> None:
        if not self.view["content"] or self.view["content"][-1].get("type") != "text":
            self.view["content"].append({"type": "text", "text": ""})
        self.view["content"][-1]["text"] += d


def _loads(s: str) -> Any:
    try:
        return json.loads(s) if s.strip() else {}
    except json.JSONDecodeError:
        return {"_unparsed": s}


def is_responses_path(path: str) -> bool:
    return path.split("?")[0].endswith("/responses")
