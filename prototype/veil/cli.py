"""veil CLI.

  veil seed SOURCE...              learn PII values: postgresql://, mysql://, mongodb://,
                                   redis://, *.sqlite, fixture dirs/files (JSON/CSV)
  veil seed-env                    learn the developer's own identity (OS user, git author)
  veil redact  < file              print the LLM's view of a file
  veil rehydrate < file            map tokens back to real values
  veil display [real|tokens]       what you see in answers (default real; tokens for screen shares)
  veil reveal [FILE]               pseudonyms -> real values (alias of rehydrate)
  veil share [FILE]                real values -> pseudonyms, safe to paste into tickets/chat
  veil proxy [--port 8787]         run the ANTHROPIC_BASE_URL proxy
  veil hook pre|post               Claude Code PreToolUse/PostToolUse hook
  veil audit [--driver ...]        run an agent session through veil, report what the LLM received
  veil init [PROJECT]              detect + seed sources, route Claude Code through veil (project-local)
  veil status [PROJECT]            proxy health, keys, vault, project wiring
  veil service install|uninstall|status   run the proxy as a macOS LaunchAgent
  veil team export|join|allow|managed-settings  share pseudonyms with a team; enforce veil via managed settings
  veil ner-model fetch             download the optional NER model (~50 MB) to ~/.veil/models
"""

from __future__ import annotations

import argparse
import json
import sys

from . import state
from .anthropic import Policy, rehydrate_tool_input
from .sources import seed, seed_environment


def _hook(veil, kind: str) -> int:
    from .hooks import hook_response
    out = hook_response(veil, kind, json.load(sys.stdin))
    if out:
        json.dump(out, sys.stdout)
    return 0


def _init(veil, args) -> int:
    import os
    from . import adopt
    project = os.path.abspath(args.project)
    sources = [] if args.no_detect else adopt.detect_sources(project)
    sources += [(s, "--source") for s in args.source]
    print(f"veil init: {project}", file=sys.stderr)
    for src, where in sources:
        print(f"  source  {adopt.redact_uri(src) if '://' in src else os.path.relpath(src, project)}   ({where})",
              file=sys.stderr)
    if args.dry_run:
        print("  (dry run: nothing seeded or written)", file=sys.stderr)
        return 0
    for src, _ in sources:
        try:
            report = seed(veil.known, src)
            print(f"  seeded  {sum(f.values for f in report.fields)} values from {len(report.fields)} fields",
                  file=sys.stderr)
        except Exception as e:  # unreachable DB etc.: keep going, report clearly
            print(f"  skipped {adopt.redact_uri(src)}: {type(e).__name__}: {str(e)[:120]}", file=sys.stderr)
    seed_environment(veil.known)
    state.save_known(veil.known, veil.vault.cipher)
    path = adopt.write_claude_settings(project, args.port, hooks=not args.no_hooks, deny_env=args.deny_env)
    print(f"  wrote   {os.path.relpath(path, project)} (ANTHROPIC_BASE_URL=http://127.0.0.1:{args.port})",
          file=sys.stderr)
    print(f"  vault   {len(veil.known)} known values", file=sys.stderr)
    if adopt.health(args.port) is None:
        print(f"  proxy   not running on :{args.port} -> start it: `veil service install` (or `veil proxy`)",
              file=sys.stderr)
    return 0


def _status(veil, args) -> int:
    import os
    from . import adopt
    h = adopt.health(args.port)
    print(f"proxy    {'up ' + json.dumps(h) if h else 'DOWN on :' + str(args.port)}")
    print(f"service  {adopt.systemd_status() if sys.platform.startswith('linux') else adopt.service_status()}")
    from . import display
    print(f"display  {display.configured_mode(state.home())} (answers show {'real values' if display.configured_mode(state.home()) == 'real' else 'pseudonyms'})")
    print(f"keys     {'env' if os.environ.get('VEIL_VAULT_KEY') else 'keychain/file'}; vault {len(veil.vault.tokens())} tokens, "
          f"{len(veil.known)} known values")
    path = os.path.join(os.path.abspath(args.project), ".claude", "settings.local.json")
    wired = os.path.exists(path) and "ANTHROPIC_BASE_URL" in open(path).read()
    print(f"project  {'routed through veil' if wired else 'not wired (run veil init)'}")
    return 0 if h and wired else 1


def _team(args) -> int:
    import os
    from . import team
    from .keys import get_key, set_key
    pw = os.environ.get(args.passphrase_env) if args.passphrase_env else None
    cfg = state.config()
    if args.action == "export":
        print(team.export_bundle(get_key("token-secret", state.home()), cfg.get("allow", []), pw))
        print("share via a password manager; it lets teammates derive the same pseudonyms "
              "(not decrypt anyone's vault)", file=sys.stderr)
    elif args.action == "join":
        if not args.value:
            raise SystemExit("usage: veil team join <bundle>")
        secret, allow = team.import_bundle(args.value[0], pw)
        vault_path = os.path.join(state.home(), "vault.db")
        veil = state.load()
        if veil.vault.tokens() and not args.reset_vault:
            raise SystemExit(f"vault already holds {len(veil.vault.tokens())} tokens derived from another secret; "
                             "re-run with --reset-vault to re-derive them with the team secret")
        where = set_key("token-secret", state.home(), secret)
        if where == "env":
            raise SystemExit("VEIL_TOKEN_SECRET is set in the environment; update it there instead")
        if args.reset_vault:
            veil.vault._db.execute("DELETE FROM entities_v2")
            veil.vault._db.commit()
        cfg["allow"] = sorted(set(cfg.get("allow", [])) | set(allow))
        state.save_config(cfg)
        print(f"joined: token secret stored in {where}; allowlist {len(cfg['allow'])} entries"
              + ("; vault reset" if args.reset_vault else ""), file=sys.stderr)
    elif args.action == "allow":
        cfg["allow"] = sorted(set(cfg.get("allow", [])) | set(args.value))
        state.save_config(cfg)
        print(f"allowlist: {cfg['allow']}", file=sys.stderr)
    else:
        doc = team.managed_settings(args.port, hooks=not args.no_hooks, lock_hooks=args.lock_hooks,
                                    display=args.display)
        with open(args.out, "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        print(f"wrote {args.out}\ninstall (admin):\n{team.install_hint(os.path.abspath(args.out))}", file=sys.stderr)
    return 0


def _service(args) -> int:
    from . import adopt
    linux = sys.platform.startswith("linux")
    if args.action == "install":
        if linux:
            path = adopt.systemd_install(args.port, args.upstream, args.ner, state.home(), capture=args.capture)
            print(f"installed {path}; status: {adopt.systemd_status()}")
        else:
            path = adopt.service_install(args.port, args.upstream, args.ner, state.home(), capture=args.capture)
            print(f"installed {path}; status: {adopt.service_status()}")
    elif args.action == "uninstall":
        print("removed" if (adopt.systemd_uninstall() if linux else adopt.service_uninstall()) else "not installed")
    else:
        print(adopt.systemd_status() if linux else adopt.service_status())
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["audit"]:
        try:  # dev harness: only in a source checkout (prototype/veil_dev), never in the package
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from veil_dev.audit import main as audit_main
        except ImportError:
            print("veil audit is a development tool: run it from a source checkout (it needs the sample datasets)",
                  file=sys.stderr)
            return 2
        return audit_main(argv[1:])
    if argv[:2] == ["ner-model", "fetch"]:
        from .ner import DEFAULT_PATH, fetch_model
        print(f"model ready in {fetch_model(DEFAULT_PATH)}", file=sys.stderr)
        return 0
    p = argparse.ArgumentParser(prog="veil")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed"); s.add_argument("sources", nargs="+")
    s = sub.add_parser("seed-sqlite"); s.add_argument("path")  # back-compat alias
    sub.add_parser("seed-env")
    sub.add_parser("redact"); sub.add_parser("rehydrate")
    s = sub.add_parser("display"); s.add_argument("mode", nargs="?", choices=["real", "tokens"])
    for name in ("reveal", "share"):
        s = sub.add_parser(name); s.add_argument("file", nargs="?", default="-")
    s = sub.add_parser("proxy"); s.add_argument("--port", type=int, default=8787)
    s.add_argument("--upstream", default="https://api.anthropic.com")
    s.add_argument("--show-tokens", action="store_true", help="don't rehydrate assistant text")
    s.add_argument("--ner", action="store_true", help="NER layer for free text (pip install veil[ner])")
    s.add_argument("--capture", metavar="DIR", help="write each upstream payload + reply (tokens only) to DIR")
    s.add_argument("--openai-upstream", metavar="URL",
                   help="OpenAI-format upstream for /chat/completions (e.g. https://api.deepseek.com)")
    s.add_argument("--bedrock-upstream", metavar="URL", help="e.g. https://bedrock-runtime.us-east-1.amazonaws.com")
    s.add_argument("--vertex-upstream", metavar="URL", help="e.g. https://us-east5-aiplatform.googleapis.com")
    s = sub.add_parser("hook"); s.add_argument("kind", choices=["pre", "post"])
    s = sub.add_parser("init"); s.add_argument("project", nargs="?", default=".")
    s.add_argument("--port", type=int, default=8787); s.add_argument("--source", action="append", default=[])
    s.add_argument("--no-detect", action="store_true"); s.add_argument("--no-hooks", action="store_true")
    s.add_argument("--deny-env", action="store_true", help="also deny Claude Code reading .env files")
    s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("status"); s.add_argument("project", nargs="?", default="."); s.add_argument("--port", type=int, default=8787)
    s = sub.add_parser("team"); s.add_argument("action", choices=["export", "join", "allow", "managed-settings"])
    s.add_argument("value", nargs="*"); s.add_argument("--passphrase-env", metavar="VAR")
    s.add_argument("--reset-vault", action="store_true"); s.add_argument("--port", type=int, default=8787)
    s.add_argument("--no-hooks", action="store_true"); s.add_argument("--lock-hooks", action="store_true")
    s.add_argument("--display", choices=["real", "tokens"], help="managed-settings: enforce pseudonyms in answers")
    s.add_argument("--out", default="50-veil.json")
    s = sub.add_parser("service"); s.add_argument("action", choices=["install", "uninstall", "status"])
    s.add_argument("--port", type=int, default=8787); s.add_argument("--upstream", default="https://api.anthropic.com")
    s.add_argument("--ner", action="store_true"); s.add_argument("--capture", metavar="DIR")
    args = p.parse_args(argv)

    if args.cmd == "service":
        return _service(args)
    if args.cmd == "display":
        from . import display
        if args.mode:
            cfg = state.config(); cfg["display"] = args.mode; state.save_config(cfg)
        mode = display.configured_mode(state.home())
        print(f"display: {mode}" + ("  (VEIL_DISPLAY overrides config)" if __import__("os").environ.get("VEIL_DISPLAY") else "")
              + ("\nnote: a managed `x-veil-display: tokens` header still forces pseudonyms" if mode == "real" else ""))
        return 0
    if args.cmd == "team":
        return _team(args)
    if args.cmd == "init" and args.dry_run:
        return _init(None, args)
    veil = state.load()
    if args.cmd == "init":
        return _init(veil, args)
    if args.cmd == "status":
        return _status(veil, args)
    if args.cmd in ("seed", "seed-sqlite"):
        for source in (args.sources if args.cmd == "seed" else [args.path]):
            report = seed(veil.known, source)
            print(f"# {source.split('@')[-1]}", file=sys.stderr)  # never echo credentials
            print(report.table(), file=sys.stderr)
        state.save_known(veil.known, veil.vault.cipher)
        print(f"{len(veil.known)} known values in total", file=sys.stderr)
    elif args.cmd == "seed-env":
        found = seed_environment(veil.known)
        state.save_known(veil.known, veil.vault.cipher)
        print(f"{len(found)} identity values learned", file=sys.stderr)
    elif args.cmd in ("reveal", "share"):
        text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        sys.stdout.write(veil.rehydrate(text) if args.cmd == "reveal" else veil.redact(text, free_text=True))
    elif args.cmd == "redact":
        sys.stdout.write(veil.redact(sys.stdin.read()))
    elif args.cmd == "rehydrate":
        sys.stdout.write(veil.rehydrate(sys.stdin.read()))
    elif args.cmd == "proxy":
        from .proxy import serve
        if args.ner:
            from .ner import GlinerDetector
            veil.ner = GlinerDetector()
        server = serve(veil, Policy(display_real=not args.show_tokens), args.port, args.upstream, args.capture,
                       args.openai_upstream, args.bedrock_upstream, args.vertex_upstream)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    elif args.cmd == "hook":
        return _hook(veil, args.kind)
    return 0


if __name__ == "__main__":
    sys.exit(main())
