# Lab: test against real router operating systems

The regression corpus in `tests/fixtures` comes from real devices. To check new OS releases, or to add
commands, run the parsers against live or emulated routers.

## 1. Start a multi-vendor lab with containerlab

[containerlab](https://containerlab.dev) runs router images as containers.

| OS | containerlab kind | how to get the image |
|---|---|---|
| Cisco IOS XR | `cisco_xrd` (XRd control-plane) or `cisco_xrv9k` | XRd from Cisco Software Download, `docker load` |
| Juniper Junos | `juniper_vjunosrouter`, `juniper_vmx` (vrnetlab) or `juniper_crpd` | Juniper downloads (vJunos-router / cRPD are free with an account) |
| Huawei VRP | `huawei_vrp` (vrnetlab, NE40E/CE images) | Huawei support portal, build with vrnetlab |

```bash
sudo containerlab deploy -t lab/clab-multivendor.yml
```

Configure some IGP/BGP/LDP between the nodes so the protocol tables have data.

## 2. Harvest every supported command

```bash
pip install -e ".[netmiko,yaml]"
export CLIJSON_USERNAME=clab CLIJSON_PASSWORD=clab@123
python scripts/harvest.py lab/inventory.yml --out harvest/
```

For each device, the harvester runs every command clijson has a dedicated parser for, plus any `extra_commands`
you add in the inventory. It saves the raw output to `harvest/<host>/<command>.txt` and prints a coverage
report:

```
host                 platform  native  generic  device-error  failed
clab-clijson-xrd1    iosxr         71        2             5       0
...
```

* **native**: parsed by a dedicated parser. Check the output, then promote it to a fixture with
  `python scripts/fixture.py add harvest/<host>/<file>.txt -p <platform> -c "<command>"`.
* **generic**: no dedicated parser yet. This is a good candidate for a new parser.
* **device-error**: the command doesn't exist on that release or platform.
* **failed**: a dedicated parser raised an exception. Please open an issue with the capture.

## 3. No lab? Use captures

Any terminal log works:

```bash
clijson parse my-session.log -m        # every command in the log, with provenance
```
