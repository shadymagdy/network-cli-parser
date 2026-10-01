# Getting started

## Install

=== "pip"

    ```bash
    pip install clijson                 # core, no dependencies
    pip install "clijson[all]"          # + YAML, pretty tables, ntc-templates fallback, MCP server
    ```

=== "uv"

    ```bash
    uv add clijson                      # add to your project
    uvx clijson parse show_bgp.txt      # run the CLI without installing
    ```

=== "pipx / uv tool"

    ```bash
    uv tool install clijson             # or: pipx install clijson
    ```

Optional extras: `yaml`, `pretty` (rich tables), `ntc` (ntc-templates engine), `genie`, `netmiko` / `scrapli`
(live collection) and `mcp` (MCP server). Python 3.10 or newer is required.

## Parse your first output

```python
import clijson

# Tell it everything...
r = clijson.parse(output, "show ipv4 interface brief", platform="iosxr")

# ...or nothing: a prompt line such as "RP/0/RP0/CPU0:PE1#show ipv4 int br" is recognised
r = clijson.parse(output)

r.data          # structured data (dict / list)
r.to_json()     # JSON string
r.records()     # the most table-like view, as flat rows
```

Every result also tells you how the answer was produced: `r.platform`, `r.command`, `r.engine` (`native`,
`structured`, `ntc`, `genie`, `generic` or `device-error`), `r.parser`, `r.confidence` and `r.warnings`.

## Same code for every vendor

Pass `normalize=True` to get the [vendor-neutral model](models.md):

```python
jobs = [("pe1-xr.txt", "show bgp summary", "iosxr"),
        ("pe2-mx.txt", "show bgp summary", "junos"),
        ("pe3-ne.txt", "display bgp peer", "vrp")]

for path, cmd, platform in jobs:
    r = clijson.parse(open(path).read(), cmd, platform, normalize=True)
    for peer in r.normalized:
        if not peer["established"]:
            print(f"{path}: {peer['neighbor']} AS{peer['remote_as']} is {peer['state']}")
```

## Pre/post maintenance checks

```python
before = clijson.parse(pre_capture, "show bgp summary", "iosxr", normalize=True)
after = clijson.parse(post_capture, "show bgp summary", "iosxr", normalize=True)
for change in clijson.diff(before, after):
    print(change)
# ~ [neighbor=10.255.0.2].state: 'Established' -> 'Idle'
```

## Whole sessions and live devices

```python
for r in clijson.parse_session(open("maintenance-window.log").read()):
    print(r.metadata.get("hostname"), r.command, r.parser)

from clijson.live import collect                       # needs clijson[scrapli] or [netmiko]
results = collect("10.0.0.1", "junos", ["show version", "show bgp summary"],
                  username="lab", password="lab123", normalize=True)
```

## Next steps

- [Command line](cli.md): everything the `clijson` command can do
- [Supported commands](commands.md): the full, generated list
- [Writing parsers](writing-parsers.md): add a command in a few lines
- [API reference](reference/api.md)
