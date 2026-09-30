"""clijson - turn router show commands into JSON.

    >>> import clijson
    >>> result = clijson.parse(raw_text, "show ip int brief", platform="iosxr")
    >>> result.data  # structured, JSON serialisable
    >>> result.to_json()

Supports Cisco IOS XR, Juniper Junos and Huawei VRP with dedicated parsers,
understands Junos ``| display json/xml`` natively, turns configurations into
trees and falls back to a heuristic engine that structures *any* output.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from .api import find_parser, parse, parse_file, parse_session, split_session, supported_commands
from .diff import Change, diff
from .exceptions import CliJsonError, ParseError, ParserNotFound, PlatformDetectionError, UnknownPlatformError
from .platforms import Platform, detect_platform, get_platform, list_platforms
from .registry import Parser, register
from .result import ParseResult

try:
    __version__ = _dist_version("clijson")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without installing
    __version__ = "0.0.0+unknown"

__all__ = [
    "Change",
    "CliJsonError",
    "ParseError",
    "ParseResult",
    "Parser",
    "ParserNotFound",
    "Platform",
    "PlatformDetectionError",
    "UnknownPlatformError",
    "__version__",
    "detect_platform",
    "diff",
    "find_parser",
    "get_platform",
    "list_platforms",
    "parse",
    "parse_file",
    "parse_session",
    "register",
    "split_session",
    "supported_commands",
]
