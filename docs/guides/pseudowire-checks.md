# Pseudowire redundancy: pre/post change checks

Adding a backup pseudowire, or moving a customer between aggregation routers, is a common change. Before it,
you want proof that the service is healthy. After it, you want proof that the primary still forwards and the
backup is a ready, standby path. clijson parses every command involved on Cisco IOS XR, Juniper Junos and Huawei
VRP. It maps them to one model, [`l2vpn.pseudowires`](../models.md#l2vpnpseudowires), so the same script checks
every vendor.

## The model

Each pseudowire becomes one record. The fields are the same whatever the vendor:

| field | meaning |
|---|---|
| `service` | VSI, bridge-domain, xconnect or attachment-circuit the PW belongs to |
| `neighbor`, `pw_id` | remote PE and PW / VC ID (together they identify the PW) |
| `state` | `up`, `standby` or `down` (Junos codes such as `HS` hot-standby or `MM` MTU mismatch are decoded) |
| `role` | `primary` / `backup` when PW redundancy is configured |
| `active` | `True` for the forwarding PW, `False` for standby or down |
| `vc_type`, `mtu`, `local_label`, `remote_label` | the parameters that must match on both ends |

## Commands by device role

=== "Access node: Huawei VRP"

    | Command | What to look at |
    |---|---|
    | `display vsi name <vsi> verbose` | VSI state, peers, `primary or secondary`, PW state and labels |
    | `display vsi name <vsi> protect-group` | protect mode, reroute policy, preference 1 **Active** / preference 2 **Inactive** |
    | `display vsi name <vsi> peer-info` | LDP session and tunnel per peer |
    | `display vsi` | summary: signaling, encapsulation, MTU and state of every VSI |
    | `display mpls l2vc [brief]` | VLL (point-to-point) VCs: AC and VC state, VC type, MTU, labels |
    | `display bridge-domain [<bd>]` | bridge-domain state and bound VSI |
    | `display mac-address bridge-domain <bd>` | MACs learned from the AC and from the PW |
    | `display mpls ldp session` | LDP sessions to both aggregation routers |

=== "Access node: Cisco IOS XR"

    | Command | What to look at |
    |---|---|
    | `show l2vpn bridge-domain bd-name <bd> detail` | AC and PW state, `Backup PW for neighbor ...`, backup PW `standby`, PW class, MTU, labels, PW status TLV |
    | `show l2vpn bridge-domain [brief]` | quick state of all bridge-domains (`Num PWs/up`) |
    | `show l2vpn xconnect detail` | the same for point-to-point cross-connects |
    | `show l2vpn forwarding bridge-domain mac-address location <loc>` | MACs learned from the AC and from `(neighbor, pw-id)` |
    | `show mpls ldp neighbor [brief]` | LDP sessions to both aggregation routers |

=== "Access node: Juniper Junos"

    | Command | What to look at |
    |---|---|
    | `show l2circuit connections [interface <ifl>] [extensive]` | primary `Up`, backup `HS` (hot-standby), PW status TLV, flow labels, labels, connection history |
    | `show vpls connections` | LDP-VPLS pseudowires per instance |
    | `show ldp session` | LDP sessions to both aggregation routers |
    | `show interfaces <ifl> extensive` | the attachment circuit, its MTU and counters |

=== "Aggregation and routing nodes"

    | Command | What to look at |
    |---|---|
    | `show l2circuit connections` | the circuit terminating the PW exists on **both** primary and backup aggregation routers |
    | `show interfaces <ae>.<unit>`, `show lacp interfaces <ae>` | the customer IFL and its bundle are up |
    | `show route instance [<instance>] [detail]` | the backup routing instance contains the customer interface |
    | `show route <prefix> table <table> extensive` | customer routes are present in the right table, with the right communities |
    | `show bgp summary [instance <instance>]`, `show bgp group <group>` | customer BGP sessions and their export/import policies |
    | `show route advertising-protocol bgp <peer> <prefix>` | the customer prefix is advertised upstream |
    | `show route forwarding-table destination <prefix> [table <table>]` | what the forwarding plane will actually use |

## Running the checks

```python
import clijson

PW_COMMANDS = {
    "vrp": ["display vsi verbose", "display vsi protect-group"],
    "iosxr": ["show l2vpn bridge-domain detail", "show l2vpn xconnect detail"],
    "junos": ["show l2circuit connections extensive"],
}


def pseudowires(capture: str, command: str, platform: str) -> list[dict]:
    return clijson.parse(capture, command, platform, normalize=True).normalized or []


# one forwarding PW per service, backups in standby, nothing down
report = clijson.checks.pseudowire_redundancy(pseudowires(capture, "show l2circuit connections", "junos"))
print(report.ok, report.problems)
```

**Pre-check.** Capture the commands above and save the results. If `clijson.checks.pseudowire_redundancy()`
already reports problems, stop: the change would build on a broken service. Pass `require_backup=True` to list the
services that don't have a backup yet.

**Post-check.** Capture again, then run `clijson.checks.pseudowire_redundancy()` and `clijson.diff()`:

```python
before = clijson.parse(pre_capture, "show l2circuit connections", "junos", normalize=True)
after = clijson.parse(post_capture, "show l2circuit connections", "junos", normalize=True)
for change in clijson.diff(before, after):
    print(change)
# + [neighbor=198.51.100.21,pw_id=3100]: {... 'state': 'standby', 'role': 'backup', ...}    <- the new backup
```

Pseudowires are matched by `neighbor` + `pw_id`, so a reordered output or new labels don't show up as changes.
Counters and timers are ignored unless you pass `ignore=None`.

**Failover test.** Inside the change window, take the primary down (shut the primary PW or its
aggregation-router IFL) and capture again. The diff should show the primary going `down` and the backup going
`standby -> up` / `active False -> True`. Then restore the primary and check that the PWs revert within the
configured revert timer.

```bash
clijson diff pre.txt failover.txt -c "show l2circuit connections" -p junos
```

**From an AI assistant.** The [MCP server](../mcp.md) has a `check_pseudowire_redundancy` tool. Give it the
post-change capture as `output` and the pre-change capture as `before`, and it returns both verdicts plus the
changes in one call.

## Common findings

| Symptom | Likely cause |
|---|---|
| Junos `MM`, or the PW stays down with matching labels | MTU differs between the two ends (compare `mtu` in the model, or the IOS XR MPLS `MTU` local/remote row) |
| Junos `EM` / `VM`, or an IOS XR PW type mismatch | VC type differs (Ethernet vs Ethernet VLAN). Compare `vc_type` on both ends. |
| PW up but traffic drops | flow-label (FAT) or control-word settings differ. See `flow_label_transmit`/`receive` and `control_word`. |
| Backup never goes standby / hot-standby | PW status TLV not negotiated on both ends (`negotiated_pw_status_tlv`, `PW Status TLV in use`) |
| Backup `down` instead of `standby` | the backup aggregation router has no matching circuit, or no LDP session to it |
