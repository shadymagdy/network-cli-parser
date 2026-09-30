"""High level API: :func:`parse`, :func:`parse_session` and friends."""

from __future__ import annotations

import os
import re
import textwrap
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .commands import CommandLine, split_command
from .engines import external
from .engines.generic import parse_generic
from .engines.structured import looks_like_json, looks_like_xml, parse_json, parse_xml
from .exceptions import ParseError, ParserNotFound, PlatformDetectionError
from .platforms import Platform, detect_platform, get_platform, match_prompt
from .registry import REGISTRY, Resolution
from .result import ParseResult
from .textutils import XR_TIMESTAMP, clean_output

DEFAULT_ENGINES: Tuple[str, ...] = ("native", "ntc", "genie", "generic")
PathLike = Union[str, "os.PathLike[str]"]


def parse(
    output: str,
    command: Optional[str] = None,
    platform: Union[str, Platform, None] = None,
    *,
    normalize: bool = False,
    engines: Optional[Sequence[str]] = None,
    strict: bool = False,
    raise_on_error: bool = False,
) -> ParseResult:
    """Parse the *output* of a show/display *command* into JSON-ready data.

    :param output:   raw text captured from the device (prompts, pagers and
                     ANSI codes are tolerated and removed)
    :param command:  the command that produced the output; abbreviations are
                     fine (``sh ip int br``). If omitted, it is read from the
                     prompt line echoed at the top of *output* when present.
    :param platform: ``"iosxr"``, ``"junos"``, ``"vrp"`` or any alias. If
                     omitted it is auto-detected from the prompt, the command
                     verb and output fingerprints.
    :param normalize: also compute a vendor-neutral view in ``result.normalized``
                     for commands that map to a common model (interfaces,
                     BGP neighbors, routes, LLDP, ...).
    :param engines:  engines to try, in order. Default:
                     ``("native", "ntc", "genie", "generic")``; unavailable
                     optional engines are skipped silently.
    :param strict:   only accept a dedicated parser; raise :class:`ParserNotFound`
                     otherwise.
    :param raise_on_error: re-raise exceptions from dedicated parsers instead
                     of falling back to the next engine.
    """
    text = clean_output(output or "")
    warnings: List[str] = []
    metadata: Dict[str, Any] = {}

    text, echoed_cmd, prompt_platform, host = _strip_prompts(text)
    if host:
        metadata["hostname"] = host
    if command is None and echoed_cmd:
        command = echoed_cmd
    if command is None:
        command = _command_from_echo(text)
    text, ts = _strip_timestamp(text)
    if ts:
        metadata["timestamp"] = ts

    if command:
        text = _strip_command_echo(text, command)
    text = textwrap.dedent(text)
    cmdline: Optional[CommandLine] = split_command(command) if command else None
    if cmdline and cmdline.filtered:
        warnings.append(f"output was filtered by '| {' | '.join(cmdline.pipes)}'; some fields may be missing")

    plat = _resolve_platform(platform, prompt_platform, text, command, metadata)
    if plat is None and cmdline is not None and cmdline.tokens and not strict:
        plat = _trial_platform(cmdline, text, metadata)

    if plat is None:
        if strict:
            raise PlatformDetectionError()
        warnings.append("platform could not be detected; using the generic engine")

    # Device already produced structured output (| display json / xml)
    fmt = cmdline.output_format if cmdline else None
    if fmt == "json" or (fmt is None and looks_like_json(text)):
        try:
            return ParseResult(parse_json(text), _name(plat), command, "json", "json", 1.0, warnings=warnings, metadata=metadata)
        except ValueError:
            if fmt == "json":
                warnings.append("output announced as JSON could not be decoded")
    if fmt == "xml" or (fmt is None and looks_like_xml(text)):
        try:
            return ParseResult(parse_xml(text), _name(plat), command, "xml", "xml", 1.0, warnings=warnings, metadata=metadata)
        except Exception:
            if fmt == "xml":
                warnings.append("output announced as XML could not be decoded")

    order = tuple(engines) if engines else DEFAULT_ENGINES
    if strict:
        order = ("native",)

    resolution: Optional[Resolution] = None
    if plat is not None and cmdline is not None and cmdline.tokens:
        resolution = REGISTRY.resolve(plat, cmdline.tokens)

    for engine in order:
        if engine == "native":
            if resolution is None:
                continue
            parser = resolution.parser(resolution.params, command or "")
            try:
                data = parser.parse(text)
            except Exception as exc:  # noqa: BLE001 - fall back to the next engine
                if raise_on_error or strict:
                    raise ParseError(parser.name, f"{type(exc).__name__}: {exc}") from exc
                warnings.append(f"{parser.name} failed ({type(exc).__name__}: {exc}); falling back")
                continue
            result = ParseResult(
                data=data,
                platform=plat.name if plat else None,
                command=command,
                engine="native",
                parser=parser.name,
                confidence=1.0,
                intent=parser.intent,
                params=dict(resolution.params),
                warnings=warnings,
                metadata=metadata,
            )
            if normalize:
                result.normalized = _normalize(parser, data, result)
            return result
        if engine in external.ENGINES:
            if plat is None or cmdline is None:
                continue
            try:
                data = external.ENGINES[engine](plat, cmdline.base, text)
            except external.EngineUnavailable:
                continue
            if data:
                return ParseResult(data, plat.name, command, engine, f"{engine}:{cmdline.base}", 0.9, warnings=warnings, metadata=metadata)
            continue
        if engine == "generic":
            data = parse_generic(text)
            if resolution is None and cmdline is not None and plat is not None:
                hints = REGISTRY.suggest(plat, cmdline.base)
                if hints:
                    warnings.append("no dedicated parser; closest supported commands: " + "; ".join(hints))
            confidence = 0.6 if data.get("tables") else 0.4
            return ParseResult(data, _name(plat), command, "generic", "generic", confidence, warnings=warnings, metadata=metadata)

    if strict and cmdline is not None and plat is not None:
        raise ParserNotFound(plat.name, cmdline.base, REGISTRY.suggest(plat, cmdline.base))
    return ParseResult(None, _name(plat), command, "none", None, 0.0, warnings=warnings + ["no engine produced a result"], metadata=metadata)


def _name(plat: Optional[Platform]) -> Optional[str]:
    return plat.name if plat else None


def _resolve_platform(
    platform: Union[str, Platform, None],
    prompt_platform: Optional[Platform],
    text: str,
    command: Optional[str],
    metadata: Dict[str, Any],
) -> Optional[Platform]:
    if platform:
        return get_platform(platform)
    if prompt_platform:
        metadata["detected_by"] = "prompt"
        return prompt_platform
    det = detect_platform(text, command)
    if det.platform:
        metadata["detected_by"] = "fingerprint"
        metadata["detection_confidence"] = det.confidence
    return det.platform


def _richness(data: Any) -> int:
    if isinstance(data, dict):
        return sum(_richness(v) for v in data.values())
    if isinstance(data, list):
        return sum(_richness(v) for v in data)
    return 0 if data in (None, "") else 1


def _trial_platform(cmdline: CommandLine, text: str, metadata: Dict[str, Any]) -> Optional[Platform]:
    """Platform unknown: let every vendor's parser try and keep the one that understands the output."""
    from .platforms import list_platforms

    best: Optional[Tuple[int, Platform]] = None
    for plat in list_platforms():
        res = REGISTRY.resolve(plat, cmdline.tokens)
        if res is None:
            continue
        try:
            score = _richness(res.parser(res.params, cmdline.raw).parse(text))
        except Exception:  # noqa: BLE001 - a failing trial simply loses
            continue
        if score and (best is None or score > best[0]):
            best = (score, plat)
    if best is None:
        return None
    metadata["detected_by"] = "trial-parse"
    return best[1]


def _strip_prompts(text: str) -> Tuple[str, Optional[str], Optional[Platform], Optional[str]]:
    """Remove a leading ``prompt#command`` echo and trailing bare prompts."""
    ls = text.split("\n")
    cmd: Optional[str] = None
    plat: Optional[Platform] = None
    host: Optional[str] = None
    # leading junk such as '{master}' or empty lines
    while ls and (not ls[0].strip() or re.match(r"^\{(?:master|backup|primary|secondary|linecard)(?::\d+)?\}\s*$", ls[0].strip())):
        ls.pop(0)
    if ls:
        hit = match_prompt(ls[0])
        if hit and hit[1].group("cmd").strip():
            plat, m = hit
            cmd = m.group("cmd").strip()
            host = m.groupdict().get("host")
            ls.pop(0)
    # trailing bare prompt(s)
    while ls and (not ls[-1].strip() or re.match(r"^\{(?:master|backup|primary|secondary)(?::\d+)?\}\s*$", ls[-1].strip())):
        ls.pop()
    while ls:
        hit = match_prompt(ls[-1])
        if hit and not hit[1].group("cmd").strip():
            plat = plat or hit[0]
            host = host or hit[1].groupdict().get("host")
            ls.pop()
            while ls and re.match(r"^\{(?:master|backup|primary|secondary)(?::\d+)?\}\s*$", ls[-1].strip()):
                ls.pop()
        else:
            break
    return "\n".join(ls), cmd, plat, host


def _strip_command_echo(text: str, command: str) -> str:
    """Drop a first line that merely repeats the command (captures without a prompt)."""
    ls = text.split("\n")
    idx = 0
    while idx < len(ls) and not ls[idx].strip():
        idx += 1
    if idx < len(ls):
        first = " ".join(ls[idx].split()).lower()
        cmd = " ".join(command.split()).lower()
        base = split_command(command).base.lower()
        if first == cmd or (first.startswith(base) and first[len(base) :].lstrip().startswith("|")) or _ECHO_ANY.match(first):
            return "\n".join(ls[idx + 1 :])
    return text


_ECHO_ANY = re.compile(r"^[#>]?\s*(?:sh|sho|show|dis|disp|display)\s+[a-z][\w\-]*(?:\s+\S+)*$", re.I)
_ECHO_RE = re.compile(r"^\s*((?:show|display)\s+[\w\-]+(?:\s+[^\n]*)?)$", re.I)


def _command_from_echo(text: str) -> Optional[str]:
    """``show bgp summary`` printed alone on the first line (capture without prompt)."""
    for ln in text.split("\n"):
        if ln.strip():
            m = _ECHO_RE.match(ln)
            if m and len(ln) < 160 and ":" not in ln.split("|")[0]:
                return m.group(1).strip()
            return None
    return None


def _strip_timestamp(text: str) -> Tuple[str, Optional[str]]:
    ls = text.split("\n")
    idx = 0
    while idx < len(ls) and not ls[idx].strip():
        idx += 1
    if idx < len(ls) and XR_TIMESTAMP.match(ls[idx]):
        ts = ls[idx].strip()
        return "\n".join(ls[:idx] + ls[idx + 1 :]).strip("\n"), ts
    return text, None


def _normalize(parser: Any, data: Any, result: ParseResult) -> Any:
    fn = getattr(parser, "normalize", None)
    if fn is None:
        return None
    try:
        return fn(data)
    except Exception as exc:  # noqa: BLE001
        result.warnings.append(f"normalization failed: {type(exc).__name__}: {exc}")
        return None


# --------------------------------------------------------------------------- #
# Sessions & files
# --------------------------------------------------------------------------- #


@dataclass
class SessionChunk:
    platform: Optional[Platform]
    hostname: Optional[str]
    command: str
    output: str


def split_session(text: str) -> List[SessionChunk]:
    """Split a captured terminal session into ``(command, output)`` chunks.

    Works with logs containing many commands (e.g. a PuTTY/SecureCRT log or a
    ``script`` capture) as long as prompts are visible.
    """
    chunks: List[SessionChunk] = []
    cur: Optional[SessionChunk] = None
    buf: List[str] = []
    for line in clean_output(text).split("\n"):
        hit = match_prompt(line)
        if hit:
            if cur is not None:
                cur.output = "\n".join(buf).strip("\n")
                chunks.append(cur)
            cur, buf = None, []
            cmd = hit[1].group("cmd").strip()
            if cmd:
                cur = SessionChunk(hit[0], hit[1].groupdict().get("host"), cmd, "")
            continue
        if cur is not None:
            buf.append(line)
    if cur is not None:
        cur.output = "\n".join(buf).strip("\n")
        chunks.append(cur)
    return chunks


def parse_session(text: str, platform: Union[str, Platform, None] = None, **kwargs: Any) -> List[ParseResult]:
    """Parse every command found in a terminal session capture."""
    results = []
    for chunk in split_session(text):
        plat = platform or chunk.platform
        res = parse(chunk.output, chunk.command, plat, **kwargs)
        if chunk.hostname:
            res.metadata.setdefault("hostname", chunk.hostname)
        results.append(res)
    return results


def parse_file(path: PathLike, command: Optional[str] = None, platform: Union[str, Platform, None] = None, **kwargs: Any) -> Union[ParseResult, List[ParseResult]]:
    """Parse a file. Session logs with several prompts yield a list of results."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if command is None and len(split_session(text)) > 1:
        return parse_session(text, platform, **kwargs)
    return parse(text, command, platform, **kwargs)


def supported_commands(platform: Union[str, Platform, None] = None) -> List[Dict[str, Any]]:
    """List the commands with dedicated parsers, optionally for one platform."""
    return REGISTRY.catalog(get_platform(platform).name if platform else None)


def find_parser(platform: Union[str, Platform], command: str) -> Optional[Resolution]:
    """Return which dedicated parser would handle *command* (``None`` if none)."""
    return REGISTRY.resolve(platform, split_command(command).tokens)
