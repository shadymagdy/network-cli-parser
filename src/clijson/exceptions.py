"""Exception hierarchy. Everything raised on purpose derives from :class:`CliJsonError`."""

from __future__ import annotations

from collections.abc import Iterable


class CliJsonError(Exception):
    """Base class for all library errors."""


class UnknownPlatformError(CliJsonError, ValueError):
    def __init__(self, name: object, known: Iterable[str] = ()):
        self.name = name
        self.known = list(known)
        hint = f" Known platforms/aliases: {', '.join(self.known)}" if self.known else ""
        super().__init__(f"Unknown platform {name!r}.{hint}")


class PlatformDetectionError(CliJsonError):
    def __init__(self, message: str = "Could not detect the platform; pass platform='iosxr' | 'junos' | 'vrp'."):
        super().__init__(message)


class ParserNotFound(CliJsonError, LookupError):
    """Raised in ``strict`` mode when no dedicated parser supports a command."""

    def __init__(self, platform: str, command: str, suggestions: list[str] | None = None):
        self.platform = platform
        self.command = command
        self.suggestions = suggestions or []
        msg = f"No parser for {command!r} on {platform}."
        if self.suggestions:
            msg += " Did you mean: " + "; ".join(self.suggestions) + "?"
        super().__init__(msg)


class ParseError(CliJsonError):
    """A dedicated parser failed on the given output."""

    def __init__(self, parser: str, message: str):
        self.parser = parser
        super().__init__(f"{parser}: {message}")


class DeviceError(CliJsonError):
    """Problem talking to a live device (``clijson.live``)."""
