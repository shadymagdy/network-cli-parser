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

## Output from RESTCONF, JSON-RPC or `ncs_cli`

`clijson.parse()` removes NSO's wrapping, so output collected outside Python parses the same way:

```bash
curl -s -u admin:admin -X POST \
  -H "Content-Type: application/yang-data+json" \
  -d '{"input": {"args": "show bgp summary"}}' \
  http://nso:8080/restconf/data/tailf-ncs:devices/device=pe1/live-status/tailf-ned-cisco-ios-xr-stats:exec/any \
  | clijson parse -c "show bgp summary" -n
```

These forms are all recognised:
- the RESTCONF response (`{"tailf-ned-cisco-ios-xr-stats:output": {"result": "..."}}`);
- a JSON-RPC envelope;
- text copied from `ncs_cli`. It starts with `result` and may carry the echoed command, in which case even the
  command and platform are detected.

## Tips

- **Long outputs** (full BGP tables, large MAC tables): raise the device's read timeout
  (`devices device pe1 read-timeout 120`) so the NED waits for the whole output.
- **Junos:** `live-status exec` needs a CLI NED. Devices managed through the NETCONF NED expose RPCs instead.
  You can still parse Junos text or `| display json` output collected another way with `clijson.parse()`.
- **What's supported:** `clijson commands -p iosxr --search l2vpn` lists the commands with dedicated parsers.
  Anything else still comes back as structured data from the generic engine.
