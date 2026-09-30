"""clijson - turn router show commands into JSON.

    >>> import clijson
    >>> result = clijson.parse(raw_text, "show ip int brief", platform="iosxr")
    >>> result.data            # structured, JSON serialisable
    >>> result.to_json()

Supports Cisco IOS XR, Juniper Junos and Huawei VRP with dedicated parsers,
understands Junos ``| display json/xml`` natively, turns configurations into
trees and falls back to a heuristic engine that structures *any* output.
"""

from .api import find_parser, parse, parse_file, parse_session, split_session, supported_commands
from .exceptions import CliJsonError, ParseError, ParserNotFound, PlatformDetectionError, UnknownPlatformError
from .platforms import Platform, detect_platform, get_platform, list_platforms
from .registry import Parser, register
from .result import ParseResult

__version__ = "0.1.0"

__all__ = [
    "parse",
    "parse_file",
    "parse_session",
    "split_session",
    "supported_commands",
    "find_parser",
    "detect_platform",
    "get_platform",
    "list_platforms",
    "Platform",
    "Parser",
    "register",
    "ParseResult",
    "CliJsonError",
    "ParseError",
    "ParserNotFound",
    "PlatformDetectionError",
    "UnknownPlatformError",
    "__version__",
]
