"""Mask secrets (passwords, keys, SNMP communities, crypt strings) in device output before it is parsed or stored.

``clijson.redact(text)`` replaces every secret with :data:`REDACTED` and keeps the surrounding syntax (keywords,
key types, quotes, ``;`` and braces), so configuration trees parse exactly as before::

    set protocols bgp group G neighbor 198.51.100.1 authentication-key "$9$abcDEF123"
    -> set protocols bgp group G neighbor 198.51.100.1 authentication-key "<redacted>"

Masked:

* Junos ``$9$...`` and ``$1$`` / ``$5$`` / ``$6$`` / ``$8$`` crypt strings, and Huawei cipher text
  (``%^%#...%^%#``, ``%$%$...%$%$``, ``@%@%...@%@%``, ``%@%@...%@%@``), wherever they appear;
* the value after ``authentication-key``, ``encrypted-password``, ``pre-shared-key`` (``ascii-text`` /
  ``hexadecimal``), ``key-string`` and ``encrypted`` (IOS XR ``password encrypted ...``,
  ``lsp-password hmac-md5 encrypted ...``, ``message-digest-key 1 md5 encrypted ...``, SNMPv3 users);
* the value after ``password`` / ``secret`` when it has a key type (IOS XR ``secret 10 ...``, ``password 7 ...``,
  ``password clear ...``, Huawei ``password cipher ...`` / ``irreversible-cipher ...``), is quoted, or is the
  statement's only value (``password s3cr3t;``);
* Huawei ``cipher <value>`` after an authentication mode, key id or community (``authentication-mode md5
  cipher ...``, ``snmp-agent community read cipher ...``);
* IOS XR ``key <n> ...``;
* SNMP communities: Junos ``snmp community <name>`` (``set`` and ``{ }`` formats), IOS XR
  ``snmp-server community <name>`` and Huawei ``snmp-agent community read|write <name>``.

Not masked, because they are settings rather than secrets: ``password minimum-length 8``, ``password expire 0``,
``authentication-order [ radius password ]``, ``ssh client cipher aes256_ctr``, a description that mentions a
password, and so on.

Every pattern is linear on any input.
"""

from __future__ import annotations

import re

__all__ = ["REDACTED", "redact"]

#: The replacement for every secret.
REDACTED = "<redacted>"

# a secret value: a quoted string, or a bare token that stops at whitespace, quotes, `;`, braces, brackets and
# backslashes (so a JSON-escaped payload keeps its escapes and `[ ... ]` lists are never swallowed)
_BARE_VALUE = r"[^\s;{}\[\]\"\\]+"
_VALUE = rf'(?P<value>"[^"\n]*"|{_BARE_VALUE})'
_TYPES = r"(?:\d+|encrypted|clear|cipher|irreversible-cipher|simple|plain|hash|ascii-text|hexadecimal)"

_CRYPT = re.compile(r"\$(?:9|1|5|6|8)\$[^\s\";'\\]+")
_HUAWEI_CIPHER_MARKS = ("%^%#", "%$%$", "@%@%", "%@%@")

# values that are always secrets
_ALWAYS = re.compile(
    r"(?P<keep>(?<![\w-])(?:authentication-key|encrypted-password|pre-shared-key|key-string)"
    rf"[ \t]+(?:(?:{_TYPES}|password)[ \t]+)*)" + _VALUE  # IOS XR: "key-string password 7 <hash>"
)
_ENCRYPTED = re.compile(r"(?P<keep>(?<![\w-])encrypted[ \t]+)" + _VALUE)
# password / secret: with a key type, or a quoted value, or the statement's only value (checked in _mask_if_last)
_TYPED = re.compile(rf"(?P<keep>(?<![\w-])(?:password|secret)[ \t]+(?:{_TYPES}[ \t]+)+)" + _VALUE)
_QUOTED = re.compile(r'(?P<keep>(?<![\w-])(?:password|secret)[ \t]+)(?P<value>"[^"\n]*")')
_BARE = re.compile(rf"(?P<keep>(?<![\w-])(?:password|secret)[ \t]+)(?P<value>{_BARE_VALUE})")
# Huawei: "authentication-mode md5 cipher X", "ospf authentication-mode md5 1 cipher X", "community read cipher X"
_HUAWEI = re.compile(
    r"(?P<keep>(?<![\w-])(?:md5|hmac-md5|hmac-sha256|sha256|hmac-sha1|keychain|read|write|\d+)[ \t]+"
    r"(?:irreversible-cipher|cipher)[ \t]+)" + _VALUE
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
    if value in (REDACTED, f'"{REDACTED}"'):
        return m.group(0)
    masked = f'"{REDACTED}"' if value.startswith('"') else REDACTED
    return m["keep"] + masked


def _ends_statement(rest: str) -> bool:
    """Nothing but ``;`` and/or a comment follows."""
    rest = rest.strip().lstrip(";").strip()
    return not rest or rest.startswith("#")


def _mask_last_bare(line: str) -> str:
    """Mask a bare ``password x`` / ``secret x`` only when *x* ends the statement (``;``, comment or line end).

    Only the last match on a line can end the statement, so the rest of the line is examined once.
    """
    last = None
    for last in _BARE.finditer(line):  # noqa: B007 - we want the final match
        pass
    if last is None or not _ends_statement(line[last.end() :]):
        return line  # more words follow: a setting such as "password minimum-length 8"
    return line[: last.start()] + _mask(last) + line[last.end() :]


def _huawei_cipher_text(line: str) -> str:
    """Mask ``%^%#...%^%#``-style cipher text as a whole, whatever it contains (one left-to-right pass)."""
    if not any(mark in line for mark in _HUAWEI_CIPHER_MARKS):
        return line
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        mark = next((mk for mk in _HUAWEI_CIPHER_MARKS if line.startswith(mk, i)), None)
        if mark is None:
            out.append(line[i])
            i += 1
            continue
        end = line.find(mark, i + len(mark))
        if end < 0:  # no closing mark: mask up to the end of the token
            stop = i
            while stop < n and not line[stop].isspace():
                stop += 1
            out.append(REDACTED)
            i = stop
        else:
            out.append(REDACTED)
            i = end + len(mark)
    return "".join(out)


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
        line = _huawei_cipher_text(line)
        line = _CRYPT.sub(REDACTED, line)
        line = _ALWAYS.sub(_mask, line)
        line = _ENCRYPTED.sub(_mask, line)
        line = _TYPED.sub(_mask, line)
        line = _QUOTED.sub(_mask, line)
        line = _mask_last_bare(line)
        line = _HUAWEI.sub(_mask, line)
        line = _XR_KEY.sub(_mask, line)
        line = _SNMP.sub(_mask, line)
        if stripped.endswith("{"):
            blocks.append(stripped.split()[0])
        elif stripped.startswith("}") and blocks:
            blocks.pop()
        out.append(line)
    return "\n".join(out)
