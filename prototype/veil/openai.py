"""OpenAI Chat Completions transforms (Aider, Continue, LiteLLM, most OpenAI-compatible
clients; any provider with an OpenAI-format endpoint: OpenAI, DeepSeek, OpenRouter, vLLM...).

Same lens as the Anthropic adapter: requests are redacted (default-deny for
unknown fields), responses are rehydrated -- text for display, tool-call
arguments per sink policy. Tool names are arbitrary here, so tools are
classified by name (shell/exec -> Bash-like, read/search -> Read-like,
write/edit/patch -> preserve); unknown tools never get real values.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .anthropic import PSEUDONYM_NOTICE, Policy, rehydrate_tool_input
from .engine import Veil
from .stream import TextHold

CONFIG = {"model", "max_tokens", "max_completion_tokens", "temperature", "top_p", "n", "stream",
          "stream_options", "stop", "seed", "tool_choice", "response_format", "reasoning_effort", "logprobs",
          "top_logprobs", "presence_penalty", "frequency_penalty", "parallel_tool_calls", "service_tier",
          "store", "modalities", "thinking"}

SHELL = re.compile(r"bash|shell|terminal|exec|command|run_?cmd|run_?terminal", re.I)
READ = re.compile(r"read|grep|search|glob|list_?(dir|files)|view|cat|find", re.I)
WRITE = re.compile(r"write|edit|patch|create_?file|replace|insert|update_?file", re.I)


def _shell_args(policy: Policy, veil: Veil, args: dict) -> dict:
    """Shell tools come as {"command": str}, {"cmd": str}, or argv lists
    (["bash", "-lc", script] or ["ls", "-la", path]). The script string gets the
    full Bash policy (escaping, egress, fragments, byte dumps); argv elements are
    passed without a shell, so they only need plain substitution."""
    key = "command" if "command" in args else "cmd"
    cmd = args.get(key)
    if isinstance(cmd, str):
        res = rehydrate_tool_input(veil, policy, "Bash", {**args, "command": cmd})
        out = {k: v for k, v in res.items() if k != "command"}
        out[key] = res["command"]
        return out
    if isinstance(cmd, list) and all(isinstance(c, str) for c in cmd):
        shell = len(cmd) >= 3 and cmd[-2] in ("-c", "-lc")
        script = cmd[-1] if shell else " ".join(cmd)
        res = rehydrate_tool_input(veil, policy, "Bash", {**args, "command": script})
        rest = {k: v for k, v in res.items() if k != "command"}
        if res["command"].startswith("echo 'veil:"):          # fragment / byte-dump notice
            return {**rest, key: ["bash", "-lc", res["command"]]}
        if shell:
            return {**rest, key: cmd[:-1] + [res["command"]]}
        if res["command"] == script and policy.mode("Bash", {"command": script}) == "none":
            return {**rest, key: cmd}                           # egress: leave tokens
        return {**rest, key: [veil.rehydrate(c) for c in cmd]}  # argv: no shell, no escaping
    return args


def rehydrate_args(veil: Veil, policy: Policy, name: str, arguments: str) -> str:
    try:
        args = json.loads(arguments) if arguments.strip() else {}
    except json.JSONDecodeError:
        return arguments  # malformed: leave as the model wrote it (tokens only)
    if not isinstance(args, dict):
        return arguments
    if name in ("Bash", "Read", "Grep", "Glob", "Edit", "Write", "MultiEdit"):
        out = rehydrate_tool_input(veil, policy, name, args)
    elif SHELL.search(name) and ("command" in args or "cmd" in args):
        out = _shell_args(policy, veil, args)
    elif WRITE.search(name):
        out = rehydrate_tool_input(veil, policy, "Edit", args)   # preserve: no new PII into files
    elif READ.search(name):
        out = rehydrate_tool_input(veil, policy, "Read", args)
    else:
        return arguments                                         # unknown sink: fail safe
    return arguments if out == args else json.dumps(out, ensure_ascii=False)


# -- requests ----------------------------------------------------------------------

def _redact_content(veil: Veil, content: Any, free_text: bool) -> Any:
    if isinstance(content, str):
        return veil.redact(content, free_text=free_text)
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") in ("text", "input_text", "output_text"):
                out.append({**part, "text": veil.redact(part.get("text", ""), free_text=free_text)})
            elif isinstance(part, dict) and part.get("type") in ("image_url", "input_audio", "file"):
                out.append(part)
            else:
                out.append(veil.redact_json(part))
        return out
    return veil.redact_json(content)


def _redact_arguments(veil: Veil, arguments: Any) -> Any:
    if not isinstance(arguments, str):
        return veil.redact_json(arguments)
    try:
        return json.dumps(veil.redact_json(json.loads(arguments)), ensure_ascii=False)
    except json.JSONDecodeError:
        return veil.redact(arguments)


def redact_chat_request(veil: Veil, body: dict, notice: bool = False) -> dict:
    out = {}
    for key, value in body.items():
        if key in CONFIG:
            out[key] = value
        elif key == "messages" and isinstance(value, list):
            msgs = []
            for m in value:
                m = dict(m)
                role = m.get("role")
                if "content" in m and m["content"] is not None:
                    m["content"] = _redact_content(veil, m["content"], free_text=role in ("user", "tool", "assistant"))
                if isinstance(m.get("tool_calls"), list):
                    m["tool_calls"] = [{**tc, "function": {**tc.get("function", {}), "arguments": _redact_arguments(
                        veil, tc.get("function", {}).get("arguments", ""))}} for tc in m["tool_calls"]]
                for k in list(m):
                    if k not in ("role", "content", "tool_calls", "tool_call_id"):
                        m[k] = veil.redact_json(m[k])  # name, reasoning_content, unknown fields
                msgs.append(m)
            out[key] = msgs
        else:  # tools, user, metadata, unknown future fields
            out[key] = veil.redact_json(value)
    if notice and out.get("tools") and isinstance(out.get("messages"), list):
        msgs = out["messages"]
        i = 0
        while i < len(msgs) and msgs[i].get("role") in ("system", "developer"):
            i += 1  # after the leading system prompt: a stable prefix keeps prompt caching
        out["messages"] = msgs[:i] + [{"role": "system", "content": PSEUDONYM_NOTICE}] + msgs[i:]
    return out


# -- responses ---------------------------------------------------------------------

def rehydrate_chat_response(veil: Veil, policy: Policy, body: dict) -> dict:
    choices = []
    for ch in body.get("choices", []):
        msg = dict(ch.get("message") or {})
        if isinstance(msg.get("content"), str) and policy.display_real:
            msg["content"] = veil.rehydrate(msg["content"])
        if isinstance(msg.get("tool_calls"), list):
            msg["tool_calls"] = [{**tc, "function": {**tc["function"], "arguments": rehydrate_args(
                veil, policy, tc["function"].get("name", ""), tc["function"].get("arguments", ""))}}
                for tc in msg["tool_calls"]]
        choices.append({**ch, "message": msg})
    return {**body, "choices": choices}


class ChatStreamRewriter:
    """Rewrites `data: {chunk}` events. Text deltas: incremental with hold-back.
    Tool-call deltas: buffered per call until finish_reason, then emitted whole."""

    def __init__(self, veil: Veil, policy: Policy):
        self.veil, self.policy = veil, policy
        self.text: dict[int, TextHold] = {}
        self.calls: dict[int, dict[int, dict]] = {}
        self.view: dict = {"content": [], "usage": {}, "model": None, "stop_reason": None}  # model's own view

    def feed(self, chunk: dict) -> list[dict]:
        out = []
        self.view["model"] = chunk.get("model") or self.view["model"]
        if chunk.get("usage"):
            self.view["usage"] = chunk["usage"]
        choices = []
        for ch in chunk.get("choices", []):
            idx, delta = ch.get("index", 0), dict(ch.get("delta") or {})
            if isinstance(delta.get("content"), str):
                self._view_text(delta["content"])
                if self.policy.display_real:
                    delta["content"] = self.text.setdefault(idx, TextHold(self.veil)).feed(delta["content"])
            if delta.get("tool_calls"):
                calls = self.calls.setdefault(idx, {})
                for tc in delta.pop("tool_calls"):
                    c = calls.setdefault(tc.get("index", 0), {"id": None, "type": "function", "name": "", "arguments": ""})
                    c["id"] = tc.get("id") or c["id"]
                    fn = tc.get("function") or {}
                    c["name"] += fn.get("name") or ""
                    c["arguments"] += fn.get("arguments") or ""
            if ch.get("finish_reason"):
                self.view["stop_reason"] = ch["finish_reason"]
                tail = self.text.pop(idx).flush() if idx in self.text else ""
                if tail:
                    delta["content"] = (delta.get("content") or "") + tail
                if idx in self.calls:
                    delta["tool_calls"] = []
                    for i, c in sorted(self.calls.pop(idx).items()):
                        self.view["content"].append({"type": "tool_use", "name": c["name"], "input": _loads(c["arguments"])})
                        delta["tool_calls"].append({"index": i, "id": c["id"], "type": "function", "function": {
                            "name": c["name"], "arguments": rehydrate_args(self.veil, self.policy, c["name"], c["arguments"])}})
            if delta or ch.get("finish_reason") or not ch.get("delta"):
                choices.append({**ch, "delta": delta})
        if choices or not chunk.get("choices"):
            out.append({**chunk, "choices": choices})
        return out

    def _view_text(self, t: str) -> None:
        if not self.view["content"] or self.view["content"][-1].get("type") != "text":
            self.view["content"].append({"type": "text", "text": ""})
        self.view["content"][-1]["text"] += t


def _loads(s: str) -> Any:
    try:
        return json.loads(s) if s.strip() else {}
    except json.JSONDecodeError:
        return {"_unparsed": s}


def is_chat_path(path: str) -> bool:
    p = path.split("?")[0]
    return p.endswith("/chat/completions")
