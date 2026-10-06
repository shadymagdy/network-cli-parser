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
* IOS XR ``key <n> ...`` and the community of ``snmp-server host <addr> traps|informs [version 1|2c] ...``;
* Huawei ``authentication plain|cipher ...`` (RSVP-TE) and ``md5-password plain|cipher <peer> ...`` (LDP);
* SNMP communities: Junos ``snmp community <name>`` (``set`` and ``{ }`` formats), IOS XR
  ``snmp-server community <name>`` and Huawei ``snmp-agent community read|write <name>``.

Not masked, because they are settings rather than secrets: ``password minimum-length 8``, ``password expire 0``,
``authentication-order [ radius password ]``, ``ssh client cipher aes256_ctr``, a description or remark that
mentions a password or a secret, and so on.

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

# a secret keyword, optional key types (IOS XR "7" / "10" / "encrypted", Huawei "cipher", Junos "ascii-text") and a
# value. The value is masked only when it is quoted, ends the statement or looks like a hash, so keywords that
# follow a key id ("authentication-key 1 type md5", "key 0 start-time ...") are never taken for secrets.
_KEYWORD = re.compile(
    r"(?P<keep>(?<![\w-])(?:password|secret|authentication-key|encrypted-password|pre-shared-key|key-string)"
    rf"[ \t]+(?:(?:{_TYPES}|password)[ \t]+)*)" + _VALUE
)
_ENCRYPTED = re.compile(r"(?P<keep>(?<![\w-])encrypted[ \t]+)" + _VALUE)
# Huawei: "authentication-mode md5 cipher X", "ospf authentication-mode md5 1 plain X", "community read cipher X"
_HUAWEI = re.compile(
    r"(?P<keep>(?<![\w-])(?:md5|hmac-md5|hmac-sha256|sha256|hmac-sha1|keychain|simple|authentication|read|write|\d+)"
    r"[ \t]+(?:irreversible-cipher|cipher|plain)[ \t]+)" + _VALUE
)
# Huawei LDP: "md5-password plain|cipher <peer> <key>"
_HUAWEI_LDP = re.compile(r"(?P<keep>(?<![\w-])md5-password[ \t]+(?:plain|cipher)[ \t]+\S+[ \t]+)" + _VALUE)
# IOS XR: "snmp-server host <addr> traps|informs [version 1|2c] [encrypted|clear] <community>" (v3 names a user)
_XR_SNMP_HOST = re.compile(
    r"(?P<keep>(?<![\w-])snmp-server[ \t]+host[ \t]+\S+[ \t]+(?:traps|informs)[ \t]+"
    r"(?:version[ \t]+(?:1|2c)[ \t]+)?(?:(?:encrypted|clear)[ \t]+)?)(?!version\b)" + _VALUE
)
# free text in which "password" / "secret" are just words
_FREE_TEXT = re.compile(r"(?<![\w-])(?:description|remark|alias)[ \t]")
_XR_KEY = re.compile(r"(?P<keep>(?<![\w-])key[ \t]+\d+[ \t]+)" + _VALUE)
_SNMP = re.compile(
    r"(?P<keep>(?<![\w-])(?:snmp[ \t]+community|snmp-server[ \t]+community(?:[ \t]+(?:clear|encrypted))?"
    r"|snmp-agent[ \t]+community[ \t]+(?:read|write))[ \t]+)(?!cipher\b)" + _VALUE
)
# Junos `{ }` format: "community <name> {" / "community <name>;" inside the snmp block
_SNMP_BLOCK_COMMUNITY = re.compile(r"(?P<keep>^[ \t]*community[ \t]+)" + _VALUE)
_HEXISH = re.compile(r"[0-9A-Fa-f]{6,}")


def _mask(m: re.Match[str]) -> str:
    value = m["value"]
    if value in (REDACTED, f'"{REDACTED}"'):
        return m.group(0)
    masked = f'"{REDACTED}"' if value.startswith('"') else REDACTED
    return m["keep"] + masked


def _ends_statement(rest: str) -> bool:
    """Nothing but ``;``, a comment or a JSON line escape follows."""
    rest = rest.strip().removesuffix("\\r").strip().lstrip(";").strip()
    return not rest or rest.startswith("#")


def _looks_secret(value: str) -> bool:
    """A crypt string, an IOS XR type 7 / hex hash, or text already masked."""
    return value.startswith("$") or bool(_HEXISH.fullmatch(value)) or REDACTED in value


def _mask_when_secret(pattern: re.Pattern[str], line: str, *, hash_only: bool = False) -> str:
    """Mask each match whose value is quoted, ends the statement or looks like a hash (``hash_only``: the latter)."""
    out: list[str] = []
    pos = 0
    free_text = _FREE_TEXT.search(line)
    for m in pattern.finditer(line):
        value = m["value"]
        in_text = free_text is not None and free_text.start() < m.start()
        secret = _looks_secret(value) or (
            not hash_only and not in_text and (value.startswith('"') or _ends_statement(line[m.end() : m.end() + 200]))
        )
        if secret:
            out.append(line[pos : m.start()])
            out.append(_mask(m))
            pos = m.end()
    if not out:
        return line
    out.append(line[pos:])
    return "".join(out)


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
    blocks: list[str] = []  # Junos `{ }` hierarchy, to know when we are inside `snmp { ... }`
    out = []
    for line in text.split("\n"):
        # a JSON-escaped payload (NSO RESTCONF / JSON-RPC) keeps its line breaks as literal "\n"
        out.append("\\n".join(_redact_line(part, blocks) for part in line.split("\\n")))
    return "\n".join(out)


def _redact_line(line: str, blocks: list[str]) -> str:
    stripped = line.strip().removesuffix("\\r").strip()
    if "snmp" in blocks:
        line = _SNMP_BLOCK_COMMUNITY.sub(_mask, line)
    line = _huawei_cipher_text(line)
    line = _CRYPT.sub(REDACTED, line)
    line = _mask_when_secret(_KEYWORD, line)
    line = _mask_when_secret(_ENCRYPTED, line, hash_only=True)
    line = _HUAWEI.sub(_mask, line)
    line = _HUAWEI_LDP.sub(_mask, line)
    line = _XR_SNMP_HOST.sub(_mask, line)
    line = _mask_when_secret(_XR_KEY, line)
    line = _SNMP.sub(_mask, line)
    if stripped.endswith("{"):
        # the first line of a wrapped payload starts with the wrapper: `{"result": "snmp {`, `<result>snmp {`
        statement = stripped.rsplit('": "', 1)[-1]
        if statement.startswith("<"):
            statement = statement.rsplit(">", 1)[-1]
        blocks.append((statement.split() or [""])[0])
    elif stripped.startswith("}") and blocks:
        blocks.pop()
    return line
