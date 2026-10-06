# Using clijson inside Cisco NSO

Cisco NSO can run any show command on a CLI-NED device with `live-status exec`:

```
admin@ncs# devices device pe1 live-status exec any "show l2vpn bridge-domain detail"
```

It returns the device's raw text in a `result` leaf, and that text is what services and actions usually need to
reason about: "is the BGP session up?", "is the backup pseudowire in standby?", "what changed after the
commit?". clijson turns that text into structured, vendor-neutral data inside your NSO Python package.

## Installing clijson for NSO

clijson is pure Python with **no dependencies**, so either way works:

=== "Into NSO's Python environment"

    ```bash
    # the python3 that NSO starts packages with (see ncs.conf /ncs-config/python-vm/start-command)
    python3 -m pip install clijson
    ```

=== "Vendored into your package"

    NSO puts each package's `python/` directory on `sys.path`, so a copy shipped inside the package is picked
    up without touching the server:

    ```bash
    python3 -m pip install --target packages/my-checks/python clijson
    ```

!!! note "Python version"
    clijson needs **Python 3.10 or newer**. NSO runs packages with the `python3` found on the server, or
    with the interpreter configured in `ncs.conf` (`/ncs-config/python-vm/start-command`). On older hosts,
    point that setting at a newer Python, for example `python3.11`.

## Running a command from Python

`clijson.nso.show()` finds the device's `live-status exec any` action, runs the command, and parses the result.
The platform comes from the device's NED (`platform name` or the NED-id), so the same code works for IOS XR,
Huawei VRP and Junos CLI NEDs:

```python
import ncs
import clijson
import clijson.nso

with ncs.maapi.single_read_trans("admin", "python") as t:
    root = ncs.maagic.get_root(t)
    device = root.devices.device["pe1"]

    bgp = clijson.nso.show(device, "show bgp summary", normalize=True)
    down = [p["neighbor"] for p in bgp.normalized if not p["established"]]
```

| Function | Returns |
|---|---|
| `clijson.nso.show(device, command, **parse_kwargs)` | a `ParseResult` (`.data`, `.normalized`, `.metadata["device"]`, ...) |
| `clijson.nso.show_many(device, [commands])` | `{command: ParseResult}` |
| `clijson.nso.exec_any(device, command)` | the raw `result` text |
| `clijson.nso.platform_of(device)` | `iosxr`, `vrp`, `junos` or `None` |

Failures raise `clijson.nso.NsoError`. That covers a device without `live-status exec` (for example a
NETCONF-NED device) and a command the device rejected.

If you already call the action yourself, pass its `result` to `clijson.parse()`:

```python
action = device.live_status.cisco_ios_xr_stats__exec.any
inp = action.get_input()
inp.args = ["show bgp summary"]
res = clijson.parse(action(inp).result, "show bgp summary", "iosxr", normalize=True)
```

## Example: a verification action

A small action package that checks pseudowire redundancy on any device and returns a verdict.

**YANG** (`packages/pw-check/src/yang/pw-check.yang`):

```yang
module pw-check {
  namespace "http://example.com/pw-check";
  prefix pwc;
  import tailf-common { prefix tailf; }
  import tailf-ncs { prefix ncs; }

  container pw-check {
    tailf:action check {
      tailf:actionpoint pw-check;
      input {
        leaf device { type leafref { path "/ncs:devices/ncs:device/ncs:name"; } mandatory true; }
        leaf command { type string; mandatory true; }
        leaf require-backup { type boolean; default true; }
      }
      output {
        leaf ok { type boolean; }
        leaf-list problem { type string; }
        leaf summary { type string; }
      }
    }
  }
}
```

**Python** (`packages/pw-check/python/pw_check/main.py`):

```python
import ncs
from ncs.dp import Action

import clijson
import clijson.nso


class Check(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output, trans):
        root = ncs.maagic.get_root(trans)
        device = root.devices.device[input.device]

        res = clijson.nso.show(device, input.command, normalize=True)
        report = clijson.checks.pseudowire_redundancy(res.normalized, require_backup=input.require_backup)

        output.ok = report.ok
        output.problem = report.problems
        output.summary = ", ".join(
            f"{s.service}: active={s.active} standby={s.standby}" for s in report.services
        )


class Main(ncs.application.Application):
    def setup(self):
        self.register_action("pw-check", Check)
```

```
admin@ncs# pw-check check device pe1 command "show l2vpn bridge-domain detail"
ok true
summary BD3100: active=['192.0.2.11'] standby=['198.51.100.21']
```

## Example: pre/post checks around a service change

Capture before the change, commit, capture again, and compare. Because pseudowires, BGP peers, interfaces and
routes are matched by their natural key, only real changes are reported:

```python
COMMANDS = ["show bgp summary", "show l2vpn bridge-domain detail"]

before = clijson.nso.show_many(device, COMMANDS, normalize=True)
# ... apply the service change and commit ...
after = clijson.nso.show_many(device, COMMANDS, normalize=True)

for cmd in COMMANDS:
    for change in clijson.diff(before[cmd], after[cmd]):
        self.log.info(f"{device.name} {cmd}: {change}")
```

Store the `before` results, for example as JSON in an operational leaf or a log, so the post-check can run in a
separate action or a later nano-service step.

## Check commands through NSO

Every command in the [pseudowire checks guide](pseudowire-checks.md) can be sent through `live-status exec any`,
and its result parses exactly like a capture taken on the device. That includes filtered commands and `ping`.
The test suite runs every regression capture through `clijson.nso.show()` on mock IOS XR, Junos and VRP NED
devices.

```python
CHECKS = {
    "iosxr": [
        "show l2vpn bridge-domain pw-id 5000",
        "show l2vpn bridge-domain bd-name 100 detail",
        "show l2vpn forwarding bridge-domain GRP-A:100 mac-address location 0/0/CPU0",
        "ping 192.0.2.18 count 5",
    ],
    "junos": [
        "show interfaces descriptions | match CUST-A",
        "show l2circuit connections interface ae2.100",
        "show vpls connections instance VPLS-A",
        "show vpls mac-table instance VPLS-A",
        "show arp no-resolve interface ae4.100",
        "show route 198.51.100.100 table inet.0",
        "show bgp summary instance VRF-B.inet.0 group GRP-A",
        "show route receive-protocol bgp 198.51.100.125 table VRF-B.inet.0",
        "ping 198.51.100.101 rapid count 5",
    ],
    "vrp": [
        "display vsi name V200 peer-info",
        "display vsi name V200 protect-group",
        "display vsi remote ldp pw-id 6000",
        "display mac-address vsi V200",
        "ping -c 5 192.0.2.18",
    ],
}

platform = clijson.nso.platform_of(device)
results = clijson.nso.show_many(device, CHECKS[platform], normalize=True)
```

Things to know when you send these through NSO:

- **Pipes.** In Python and RESTCONF the whole string goes to the device, so `show bgp summary | match 198.51.100.125`
  is filtered by the device. In `ncs_cli`, put the pipe **inside** the quotes to have the device filter
  (`exec any "show l2circuit connections | match rmt"`). A pipe after the quotes is NSO's own filter. clijson
  handles both and marks the result as filtered.
- **Quotes inside the command.** Escape them in `ncs_cli`: `exec any "show interfaces descriptions | match \"CUST A\""`.
  In Python, pass the string as is.
- **Ping.** Always give a count (`rapid count 5` on Junos, `count 5` on IOS XR, `-c 5` on VRP), or the command
  will not return before the NED's read timeout. The `ping` model gives `sent`, `received`, `loss_percent`,
  `success` and the round-trip times, so pre and post results are easy to compare.
- **Paging.** The CLI NEDs turn off paging when they connect, so `| no-more` is optional. It's harmless if you keep it.

## Output from RESTCONF, JSON-RPC or `ncs_cli`

`clijson.parse()` removes NSO's wrapping, so output collected outside Python parses the same way:

```bash
curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  -d '{"input": {"args": "show bgp summary"}}' \
  http://nso:8080/restconf/data/tailf-ncs:devices/device=pe1/live-status/tailf-ned-cisco-ios-xr-stats:exec/any \
  | clijson parse -c "show bgp summary" -n
```

Every way NSO hands back the `result` is recognised:

| How the output was collected | What clijson receives |
|---|---|
| Python API: `action(inp).result` | the text, usually with CRLF line endings and the device prompt at the end |
| RESTCONF (JSON) or `ncs_cli ... \| display json` | `{"<ned>-stats:output": {"result": "..."}}` |
| RESTCONF (XML), NETCONF, or `ncs_cli ... \| display xml` | `<result xmlns="...">...</result>`, XML-escaped, possibly inside `<rpc-reply>` |
| JSON-RPC `run_action` | `{"jsonrpc": "2.0", "result": {...}}` or `"result": [{"name": "result", "value": "..."}]` |
| `ncs_cli` transcript (C-style or J-style) | NSO's prompt and `devices device X live-status exec any "..."` line, `result`, the text, `[ok][...]` and NSO's prompt again (also with NSO's own `\| match` after the command, which removes the `result` line) |
| copied out of a log or JSON string | the same text with literal `\r\n` instead of line breaks |

For a transcript, the device name and the command are read from NSO's command line, so
`clijson.parse(transcript)` needs no hints at all. NSO's own prompt (`admin@ncs>`) is never mistaken for a Junos
prompt. Commands sent from configuration mode (`do show ...` on IOS XR, `run show ...` on Junos) resolve to
the same parsers.

!!! success "Tested on the whole corpus"
    Every regression capture of every supported platform is parsed through each of the forms above. The test
    suite requires the result to be identical to parsing the plain capture.

## Masking secrets

Configuration commands return passwords, keys and SNMP communities as the device prints them. Pass
`redact=True` to mask them before parsing, in both `data` and `raw`:

```python
res = clijson.nso.show(device, "show configuration | display set", redact=True)
res.metadata["redacted"]   # True
```

The same flag exists on `clijson.parse()`, `parse_file()`, `parse_session()` and `clijson.nso.show_many()`, and
`clijson.redact(text)` masks any text, for example before you store a capture. Every secret becomes
`<redacted>`, and keywords, quotes and `;` stay in place, so configuration trees parse the same.

## Stripping NSO wrapping yourself

`clijson.parse()` removes NSO's wrapping by itself. When you need the device text, for example to store or hash
it, use the stable `clijson.nso.unwrap(payload)`. It accepts every format in the table above and returns plain
text:

```python
text = clijson.nso.unwrap(restconf_response_body)
```

## Tips

- **Long outputs** (full BGP tables, large MAC tables): raise the device's read timeout
  (`devices device pe1 read-timeout 120`) so the NED waits for the whole output.
- **Junos:** `live-status exec` needs a CLI NED. Devices managed through the NETCONF NED expose RPCs instead.
  You can still parse Junos text or `| display json` output collected another way with `clijson.parse()`.
- **What's supported:** `clijson commands -p iosxr --search l2vpn` lists the commands with dedicated parsers.
  Anything else still comes back as structured data from the generic engine.
