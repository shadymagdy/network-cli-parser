"""``clijson`` command line interface.

    clijson parse show_bgp.txt -p iosxr -c "show bgp summary"
    ssh r1 "show interfaces terse" | clijson parse -p junos -c "show interfaces terse"
    clijson parse session.log                      # every command in a terminal log
    clijson parse out.txt -c "dis int br" --normalize -f table
    clijson commands -p vrp --search bgp
    clijson diff pre.txt post.txt -c "show bgp summary"   # what changed?
    clijson detect out.txt
    clijson serve --port 8080                      # tiny HTTP API
    clijson run 10.0.0.1 -p iosxr -c "show version" -u admin   # live device (netmiko/scrapli)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, List, Optional, Sequence

from . import __version__
from .api import parse, parse_session, split_session, supported_commands
from .engines.external import available_engines
from .exceptions import CliJsonError
from .platforms import detect_platform, list_platforms
from .result import ParseResult, _rows

SUBCOMMANDS = {"parse", "diff", "commands", "detect", "platforms", "serve", "run", "version"}


def _rich_console():  # pragma: no cover - cosmetic
    try:
        from rich.console import Console

        return Console()
    except ImportError:
        return None


def _read_input(path: Optional[str]) -> str:
    if not path or path == "-":
        if sys.stdin.isatty():
            raise SystemExit("error: no input file given and nothing piped on stdin (try: clijson parse FILE -c 'show ...')")
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _emit(obj: Any, fmt: str, stream=None) -> None:
    stream = stream or sys.stdout
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise SystemExit("error: YAML output needs PyYAML (pip install 'clijson[yaml]')") from None
        stream.write(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True))
        return
    if fmt == "table":
        if _print_table(obj):
            return
        fmt = "json"
    text = json.dumps(obj, indent=None if fmt == "json-compact" else 2, default=str)
    console = _rich_console() if stream is sys.stdout and sys.stdout.isatty() and fmt == "json" else None
    if console is not None:  # pragma: no cover - cosmetic
        from rich.syntax import Syntax

        console.print(Syntax(text, "json", theme="ansi_dark", word_wrap=True, background_color="default"))
    else:
        stream.write(text + "\n")


def _print_table(obj: Any) -> bool:
    rows = _rows(obj)
    if not rows:
        return False
    cols: List[str] = []
    for r in rows:
        for k, v in r.items():
            if k not in cols and not isinstance(v, (dict, list)):
                cols.append(k)
    console = _rich_console()
    if console is not None:  # pragma: no cover - cosmetic
        from rich.table import Table

        t = Table(show_lines=False, header_style="bold cyan")
        for c in cols:
            t.add_column(c)
        for r in rows:
            t.add_row(*["" if r.get(c) is None else str(r.get(c)) for c in cols])
        console.print(t)
        return True
    widths = {c: max(len(c), *(len(str(r.get(c, "") if r.get(c) is not None else "")) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(("" if r.get(c) is None else str(r.get(c))).ljust(widths[c]) for c in cols))
    return True


def _result_payload(res: ParseResult, args: argparse.Namespace) -> Any:
    if args.meta:
        return res.to_dict(meta=True)
    if args.normalize and res.normalized is not None:
        return res.normalized
    return res.data


def cmd_parse(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    engines = args.engine.split(",") if args.engine else None
    kwargs = dict(normalize=args.normalize, engines=engines, strict=args.strict)
    results: List[ParseResult]
    if args.command is None and len(split_session(text)) > 1:
        results = parse_session(text, args.platform, **kwargs)
        payload: Any = [r.to_dict(meta=True) if args.meta else {"command": r.command, "platform": r.platform, "data": _result_payload(r, args)} for r in results]
    else:
        res = parse(text, args.command, args.platform, **kwargs)
        results = [res]
        payload = _result_payload(res, args)
    _emit(payload, args.format)
    if not args.quiet:
        for r in results:
            for w in r.warnings:
                print(f"warning: {w}", file=sys.stderr)
            if r.engine == "generic" and not r.warnings:
                print("note: parsed with the heuristic generic engine", file=sys.stderr)
    return 0 if all(r.ok or r.data == [] or r.data == {} for r in results) else 1


def cmd_diff(args: argparse.Namespace) -> int:
    from .diff import diff

    before = parse(_read_input(args.before), args.command, args.platform, normalize=not args.native)
    after = parse(_read_input(args.after), args.command or before.command, args.platform or before.platform, normalize=not args.native)
    changes = diff(before, after, ignore=None if args.all else diff.__defaults__[0], normalized=not args.native)
    if args.format == "text":
        if not changes:
            print("no differences")
        for c in changes:
            print(c)
    else:
        _emit([{"path": c.path, "kind": c.kind, "before": c.before, "after": c.after} for c in changes], args.format)
    return 1 if changes else 0


def cmd_commands(args: argparse.Namespace) -> int:
    rows = supported_commands(args.platform)
    if args.search:
        needle = args.search.lower()
        rows = [r for r in rows if needle in r["command"].lower() or needle in (r["description"] or "").lower() or needle in (r["intent"] or "")]
    if args.format in ("json", "yaml", "json-compact"):
        _emit(rows, args.format)
    else:
        _print_table([{"platform": r["platform"], "command": r["command"], "intent": r["intent"] or "", "description": r["description"]} for r in rows])
        print(f"\n{len(rows)} command patterns", file=sys.stderr)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    text = _read_input(args.file)
    chunks = split_session(text)
    det = detect_platform(text, chunks[0].command if chunks else None)
    out = {
        "platform": det.platform.name if det.platform else None,
        "display_name": det.platform.display_name if det.platform else None,
        "confidence": det.confidence,
        "scores": det.scores,
        "reasons": det.reasons[:10],
    }
    if chunks:
        out["commands"] = [c.command for c in chunks]
    _emit(out, args.format)
    return 0 if det.platform else 1


def cmd_platforms(args: argparse.Namespace) -> int:
    rows = [{"name": p.name, "vendor": p.vendor, "display_name": p.display_name, "verb": p.verb, "aliases": ", ".join(p.aliases)} for p in list_platforms()]
    if args.format == "table":
        _print_table(rows)
    else:
        _emit(rows, args.format)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:  # pragma: no cover - network server
    from .server import serve

    serve(args.host, args.port)
    return 0


def cmd_run(args: argparse.Namespace) -> int:  # pragma: no cover - needs a device
    from .live import collect

    password = args.password or os.environ.get("CLIJSON_PASSWORD")
    if password is None and sys.stdin.isatty():
        import getpass

        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    results = collect(args.host, args.platform, args.command, username=args.username, password=password, port=args.port, normalize=args.normalize)
    payload = {r.command: (r.normalized if args.normalize and r.normalized is not None else r.data) for r in results}
    _emit(payload if len(results) > 1 else next(iter(payload.values())), args.format)
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    info = {"clijson": __version__, "python": sys.version.split()[0], "engines": {"native": True, "generic": True, **available_engines()}}
    info["commands"] = len(supported_commands())
    _emit(info, "json")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="clijson", description="Turn router show commands (Cisco IOS XR, Juniper Junos, Huawei VRP) into JSON.")
    p.add_argument("--version", action="version", version=f"clijson {__version__}")
    sub = p.add_subparsers(dest="cmd")

    fmt_help = "output format: json (default), yaml, table, json-compact"

    sp = sub.add_parser("parse", help="parse command output from a file or stdin")
    sp.add_argument("file", nargs="?", help="file with the output ('-' or omitted = stdin)")
    sp.add_argument("-c", "--command", help="command that produced the output (abbreviations OK); auto-read from the prompt line when omitted")
    sp.add_argument("-p", "--platform", help="iosxr | junos | vrp (or any alias); auto-detected when omitted")
    sp.add_argument("-n", "--normalize", action="store_true", help="emit the vendor-neutral model when available")
    sp.add_argument("-m", "--meta", action="store_true", help="include provenance (engine, parser, confidence, warnings)")
    sp.add_argument("-f", "--format", default="json", choices=["json", "yaml", "table", "json-compact"], help=fmt_help)
    sp.add_argument("-e", "--engine", help="comma separated engine order, e.g. native,generic")
    sp.add_argument("--strict", action="store_true", help="fail unless a dedicated parser exists")
    sp.add_argument("-q", "--quiet", action="store_true", help="suppress warnings on stderr")
    sp.set_defaults(func=cmd_parse)

    sdf = sub.add_parser("diff", help="structural diff of two captures (pre/post change check)")
    sdf.add_argument("before")
    sdf.add_argument("after")
    sdf.add_argument("-c", "--command")
    sdf.add_argument("-p", "--platform")
    sdf.add_argument("--native", action="store_true", help="compare native output instead of the normalized view")
    sdf.add_argument("--all", action="store_true", help="also report counters, timers and uptimes")
    sdf.add_argument("-f", "--format", default="text", choices=["text", "json", "yaml", "json-compact"])
    sdf.set_defaults(func=cmd_diff)

    sc = sub.add_parser("commands", help="list commands with dedicated parsers")
    sc.add_argument("-p", "--platform")
    sc.add_argument("-s", "--search", help="filter by text")
    sc.add_argument("-f", "--format", default="table", choices=["table", "json", "yaml", "json-compact"])
    sc.set_defaults(func=cmd_commands)

    sd = sub.add_parser("detect", help="detect the platform of some output")
    sd.add_argument("file", nargs="?")
    sd.add_argument("-f", "--format", default="json", choices=["json", "yaml", "json-compact"])
    sd.set_defaults(func=cmd_detect)

    spl = sub.add_parser("platforms", help="list supported platforms and aliases")
    spl.add_argument("-f", "--format", default="table", choices=["table", "json", "yaml"])
    spl.set_defaults(func=cmd_platforms)

    ss = sub.add_parser("serve", help="run a small HTTP API (POST /parse)")
    ss.add_argument("--host", default="127.0.0.1")
    ss.add_argument("--port", type=int, default=8080)
    ss.set_defaults(func=cmd_serve)

    sr = sub.add_parser("run", help="run commands on a live device and parse them (needs netmiko or scrapli)")
    sr.add_argument("host")
    sr.add_argument("-p", "--platform", required=True)
    sr.add_argument("-c", "--command", action="append", required=True, help="repeat for several commands")
    sr.add_argument("-u", "--username", default=os.environ.get("CLIJSON_USERNAME", os.environ.get("USER", "admin")))
    sr.add_argument("--password", help="or set CLIJSON_PASSWORD; prompted when omitted")
    sr.add_argument("--port", type=int, default=22)
    sr.add_argument("-n", "--normalize", action="store_true")
    sr.add_argument("-f", "--format", default="json", choices=["json", "yaml", "table", "json-compact"])
    sr.set_defaults(func=cmd_run)

    sv = sub.add_parser("version", help="show version and available engines")
    sv.set_defaults(func=cmd_version)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `clijson FILE -c ...` is shorthand for `clijson parse FILE -c ...`
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv = ["parse"] + argv
    elif not argv and not sys.stdin.isatty():
        argv = ["parse"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except CliJsonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
