"""Mask secrets (passwords, keys, SNMP communities, crypt strings) in device output before it is parsed or stored.

``clijson.redact(text)`` replaces every secret with :data:`REDACTED` and keeps the surrounding syntax (keywords,
key types, quotes, ``;`` and braces), so configuration trees parse exactly as before::

    set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$abcDEF123"
    -> set protocols bgp group G neighbor 198.51.100.1 authentication-key "<redacted>"

Covered:

* Junos ``$9$...`` and ``$1$`` / ``$5$`` / ``$6$`` / ``$8$`` crypt strings, wherever they appear;
* the value after ``authentication-key``, ``encrypted-password``, ``pre-shared-key`` (``ascii-text`` /
  ``hexadecimal``), ``secret``, ``password``, ``cipher`` and ``irreversible-cipher``, including a key type such as
  IOS XR ``secret 10 ...``, ``password 7 ...``, ``password encrypted ...`` and Huawei ``password cipher ...``;
* IOS XR ``key <n> ...``;
* SNMP communities: Junos ``snmp community <name>`` (``set`` and ``{ }`` formats), IOS XR
  ``snmp-server community <name>`` and Huawei ``snmp-agent community read|write <name>``.

Every pattern is linear on any input (no nested quantifiers over the same characters).
"""

from __future__ import annotations

import re

__all__ = ["REDACTED", "redact"]

#: The replacement for every secret.
REDACTED = "<redacted>"

# a secret value: a quoted string, or a bare token that stops at whitespace, quotes, `;`, braces and backslashes
# (so a JSON-escaped payload keeps its escapes)
_VALUE = r'(?P<value>"[^"\n]*"|[^\s;{}"\\]+)'

_CRYPT = re.compile(r"\$(?:9|1|5|6|8)\$[^\s\";'\\]+")

_KEYWORD = re.compile(
    r"(?P<keep>(?<![\w-])(?:authentication-key|encrypted-password|pre-shared-key|secret|password"
    r"|irreversible-cipher|(?<!server )cipher)"
    r"[ \t]+(?:(?:\d+|encrypted|clear|ascii-text|hexadecimal|cipher|irreversible-cipher|simple|plain)[ \t]+)*)" + _VALUE
)
_XR_KEY = re.compile(r"(?P<keep>(?<![\w-])key[ \t]+\d+[ \t]+)" + _VALUE)
_SNMP = re.compile(
    r"(?P<keep>(?<![\w-])(?:snmp[ \t]+community|snmp-server[ \t]+community(?:[ \t]+(?:clear|encrypted))?"
    r"|snmp-agent[ \t]+community[ \t]+(?:read|write))[ \t]+)(?!cipher\b)" + _VALUE
)
# Junos `{ }` format: "community <name> {" / "community <name>;" inside the snmp block
_SNMP_BLOCK_COMMUNITY = re.compile(r"(?P<keep>^[ \t]*community[ \t]+)" + _VALUE)


def _mask(m: re.Match[str]) -> str:
    value = m["value"]
    masked = f'"{REDACTED}"' if value.startswith('"') else REDACTED
    return m["keep"] + masked


def redact(text: str) -> str:
    """Return *text* with every recognised secret replaced by :data:`REDACTED` (see the module docs)."""
    if not text:
        return text
    out = []
    blocks: list[str] = []  # Junos `{ }` hierarchy, to know when we are inside `snmp { ... }`
    for line in text.split("\n"):
        stripped = line.strip()
        if "snmp" in blocks:
            line = _SNMP_BLOCK_COMMUNITY.sub(_mask, line)
        line = _CRYPT.sub(REDACTED, line)
        line = _KEYWORD.sub(_mask, line)
        line = _XR_KEY.sub(_mask, line)
        line = _SNMP.sub(_mask, line)
        if stripped.endswith("{"):
            blocks.append(stripped.split()[0])
        elif stripped.startswith("}") and blocks:
            blocks.pop()
        out.append(line)
    return "\n".join(out)
