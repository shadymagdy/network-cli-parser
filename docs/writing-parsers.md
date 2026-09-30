# Writing a parser

A parser is a class with a `parse(text)` method, registered for one or more command patterns.

```python
import re
from clijson import Parser, register
from clijson.models import record, status
from clijson.textutils import match_lines, none_if

@register("vrp", "display vrrp [brief]", "display vrrp <interface> [brief]")
class DisplayVrrpBrief(Parser):
    """VRRP groups: state, interface, virtual IP."""

    def parse(self, text):
        out = []
        for m in match_lines(r"^\s*(?P<vrid>\d+)\s+(?P<state>Master|Backup|Initialize)\s+(?P<intf>\S+)\s+(?P<type>\S+)\s+(?P<vip>\S+)", text):
            out.append({"vrid": int(m["vrid"]), "state": m["state"], "interface": m["intf"], "type": m["type"], "virtual_ip": m["vip"]})
        return out
```

## Command patterns

| syntax | meaning | example |
|---|---|---|
| `word` | keyword (abbreviations accepted) | `show` matches `sh` |
| `<name>` | one token captured as `self.params["name"]` | `show interfaces <interface>` |
| `<name...>` | rest of the line | `show route [<target...>]` |
| `[ ... ]` | optional, may nest | `show bgp [vrf <vrf>] summary` |
| `( a \| b )` | alternatives | `show (ip\|ipv4) interface brief` |

Tips:

* Register the **most specific** patterns you can. More keywords means a higher score. For example,
  `show route summary` wins over `show route [<target...>]`.
* For commands whose options can come in any order (Junos `show route ...`), register a catch-all
  `<args...>` and read the options in the parser (`self.params["args"]`).
* `self.command` holds the command exactly as the user typed it. It is useful for things like the address family.

## Helpers (`clijson.textutils`)

| helper | use |
|---|---|
| `match_lines(rx, text)` | per-line regex matching (never spans lines) |
| `parse_table(text, header=..., names=...)` | column-aligned tables sliced by header position |
| `blocks(text, start=rx)` | split output into per-entity blocks |
| `to_num`, `none_if`, `snake`, `normalize_mac`, `parse_duration` | value helpers |
| `compact(obj)` | drop `None` / empty values |
| `search(rx, text)` | first match as a dict of converted groups |

## Normalized output

If the command maps to a common concept, pass `intent="..."` to `@register` and implement `normalize(data)`.
It should return records built with `clijson.models.record(intent, **fields)`, which rejects unknown fields
and fills in missing ones. Use `status()`, `mac()` and `seconds()` to standardise values. The schemas are in
[models.md](models.md).

## Fixtures (tests)

```bash
python scripts/fixture.py add capture.txt -p vrp -c "display vrrp brief" --name ne40e_v8r21
pytest tests/test_fixtures.py -k vrrp
```

The generated `.json` file holds the expected output. **Review it before you commit.** After an intentional
change, `python scripts/fixture.py update` rewrites every expectation so you can check the diff with git.

## Shipping parsers from your own package

```toml
# your pyproject.toml
[project.entry-points."clijson.parsers"]
my_parsers = "my_package.clijson_parsers"
```

clijson imports that module on first use, and your `@register` decorators run.
