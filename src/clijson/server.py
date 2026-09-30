"""Dependency-free HTTP API so non-Python tools can use the parsers.

    $ clijson serve --port 8080
    $ curl -s localhost:8080/parse -d '{"platform": "iosxr", "command": "show ip int brief", "output": "..."}'

Endpoints
---------
``POST /parse``      body ``{"output", "command"?, "platform"?, "normalize"?}``
``GET  /commands``   supported commands (``?platform=junos``)
``GET  /health``     liveness probe
"""

from __future__ import annotations

import contextlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from . import __version__
from .api import parse, supported_commands
from .exceptions import CliJsonError

MAX_BODY = 20 * 1024 * 1024


def handle(method: str, path: str, body: bytes) -> Tuple[int, Dict[str, Any]]:
    """Pure request handler (easy to test without sockets)."""
    url = urlparse(path)
    if method == "GET" and url.path == "/health":
        return 200, {"status": "ok", "version": __version__}
    if method == "GET" and url.path == "/commands":
        qs = parse_qs(url.query)
        try:
            return 200, {"commands": supported_commands((qs.get("platform") or [None])[0])}
        except CliJsonError as exc:
            return 400, {"error": str(exc)}
    if method == "POST" and url.path == "/parse":
        try:
            req = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            return 400, {"error": f"invalid JSON body: {exc}"}
        if not isinstance(req, dict) or not isinstance(req.get("output"), str):
            return 400, {"error": "body must be an object with a string 'output' field"}
        try:
            res = parse(
                req["output"],
                req.get("command"),
                req.get("platform"),
                normalize=bool(req.get("normalize")),
                strict=bool(req.get("strict")),
            )
        except CliJsonError as exc:
            return 422, {"error": str(exc)}
        return 200, res.to_dict(meta=True)
    return 404, {"error": f"no route for {method} {url.path}"}


class _Handler(BaseHTTPRequestHandler):  # pragma: no cover - exercised manually
    server_version = f"clijson/{__version__}"

    def _send(self, code: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._send(*handle("GET", self.path, b""))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, {"error": "body too large"})
            return
        self._send(*handle("POST", self.path, self.rfile.read(length)))

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:  # pragma: no cover
    httpd = ThreadingHTTPServer((host, port), _Handler)
    with contextlib.suppress(KeyboardInterrupt):
        httpd.serve_forever()
