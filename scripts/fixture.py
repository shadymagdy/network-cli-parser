#!/usr/bin/env python3
"""Manage regression fixtures.

Every fixture is a pair of files under ``tests/fixtures/<platform>/<command_slug>/``:

* ``<name>.txt``  - raw device output, exactly as captured
* ``<name>.json`` - ``{"command", "platform", "source", "expected", "normalized"?}``

Usage::

    # add a new fixture from a capture (review the generated JSON!)
    python scripts/fixture.py add -p iosxr -c "show ipv4 interface brief" capture.txt --name ncs5500

    # re-generate every expected output after an intentional parser change
    python scripts/fixture.py update            # then review `git diff tests/fixtures`

    # check fixtures without pytest
    python scripts/fixture.py check
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import clijson  # noqa: E402
from clijson.commands import slugify  # noqa: E402
from clijson.platforms import get_platform  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def _render(txt: Path, meta: dict) -> dict:
    res = clijson.parse(txt.read_text(encoding="utf-8"), meta["command"], meta["platform"], normalize=True)
    if res.engine != "native":
        raise SystemExit(f"{txt}: parsed by {res.engine!r} engine, expected a native parser ({res.warnings})")
    out = {k: meta[k] for k in ("command", "platform", "source") if k in meta}
    out["expected"] = res.data
    if res.normalized is not None:
        out["normalized"] = res.normalized
    return out


def cmd_add(args: argparse.Namespace) -> int:
    plat = get_platform(args.platform).name
    folder = FIXTURES / plat / slugify(args.command)
    folder.mkdir(parents=True, exist_ok=True)
    name = args.name or Path(args.file).stem
    txt = folder / f"{name}.txt"
    shutil.copyfile(args.file, txt)
    meta = {"command": args.command, "platform": plat, "source": args.source}
    (folder / f"{name}.json").write_text(json.dumps(_render(txt, meta), indent=2) + "\n", encoding="utf-8")
    print(f"created {txt.relative_to(ROOT)} (+ .json) - review the expected output before committing")
    return 0


def _pairs():
    for js in sorted(FIXTURES.rglob("*.json")):
        txt = js.with_suffix(".txt")
        if txt.exists():
            yield txt, js


def cmd_update(args: argparse.Namespace) -> int:
    n = 0
    for txt, js in _pairs():
        meta = json.loads(js.read_text(encoding="utf-8"))
        new = _render(txt, meta)
        if new != meta:
            js.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
            print(f"updated {js.relative_to(ROOT)}")
            n += 1
    print(f"{n} fixture(s) updated")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    bad = 0
    total = 0
    for txt, js in _pairs():
        total += 1
        meta = json.loads(js.read_text(encoding="utf-8"))
        if _render(txt, meta) != meta:
            bad += 1
            print(f"MISMATCH {js.relative_to(ROOT)}")
    print(f"{total - bad}/{total} fixtures OK")
    return 1 if bad else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("file")
    a.add_argument("-p", "--platform", required=True)
    a.add_argument("-c", "--command", required=True)
    a.add_argument("--name")
    a.add_argument("--source", default="contributed")
    a.set_defaults(func=cmd_add)
    sub.add_parser("update").set_defaults(func=cmd_update)
    sub.add_parser("check").set_defaults(func=cmd_check)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
