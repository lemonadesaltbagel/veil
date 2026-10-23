"""Claude Code hook logic, shared by the local hook process and the proxy endpoint."""

from __future__ import annotations

import os
import secrets

from .anthropic import Policy, rehydrate_tool_input


def hook_response(veil, kind: str, event: dict) -> dict | None:
    if kind == "post":
        original = event.get("tool_response")
        redacted = veil.redact_json(original)
        if redacted != original:
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": redacted}}
    else:
        original = event.get("tool_input", {})
        from .anthropic import configured_aliases
        from .state import config
        policy = Policy(tool_aliases=configured_aliases(config()))
        updated = rehydrate_tool_input(veil, policy, event.get("tool_name", ""), original)
        if updated != original:
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": updated}}
    return None


def hook_secret(home: str) -> str:
    """Shared secret between hook clients and the proxy's /veil/hook endpoint (0600 file).
    The endpoint can turn tokens into real values, so a local web page or other
    user must not be able to call it."""
    path = os.path.join(home, "hook.secret")
    if not os.path.exists(path):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass  # another process created it first
    return open(path).read().strip()
