"""A minimal JSON-over-HTTP service base, shared by all four services.

`http.server` from the standard library rather than a web framework: nothing
to install on a machine where we have no sudo, and no debug mode that could
leak a stack trace into a response (conformance check P-*).

The base supplies the three endpoints every service in the contract must
expose — `GET /health`, `GET /transcript`, `POST /reset` — so no service
re-implements them, and every service reports the same `spec_version`.
"""

import json
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import config
from .transcript import Transcript, clean_run_id

MAX_BODY_BYTES = 16 * 1024


class Request:
    """One inbound request, already parsed and size-limited."""

    def __init__(
        self,
        method: str,
        path: str,
        query: Dict[str, str],
        headers: Dict[str, str],
        body: Any,
        body_error: Optional[str],
        client_ip: str,
    ) -> None:
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body
        self.body_error = body_error
        self.client_ip = client_ip

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def field(self, name: str) -> Any:
        return self.body.get(name) if isinstance(self.body, dict) else None

    @property
    def run_id(self) -> str:
        """The run this request belongs to, from header, query, or body.

        The header and query forms exist because `GET /protected` carries no
        body, and step 3 still has to land in the transcript under the run_id
        the harness gave the Subject agent.
        """
        for candidate in (
            self.header("x-run-id"),
            self.query.get("run_id", ""),
            self.field("run_id"),
        ):
            cleaned = clean_run_id(candidate)
            if cleaned != "unattributed":
                return cleaned
        return "unattributed"


Response = Tuple[int, Dict[str, Any], Dict[str, str]]
Handler = Callable[[Request], Any]


class JsonService:
    """Subclass, set `name`, register routes, call `run()`."""

    name = "service"

    def __init__(self) -> None:
        self.transcript = Transcript()
        self.team = config.team_name()
        # When the service is reached through a reverse proxy that keeps the
        # path prefix (nginx `proxy_pass` without a trailing slash does), the
        # prefix arrives on every request and has to come off before routing.
        # Without this the service 404s everything and the page looks broken
        # rather than absent, which is the commonest way a proxied app fails.
        self.base_path = _normalise_base(
            config.setting("LAB1_%s_BASE_PATH" % self.name.upper(), "LAB1_BASE_PATH")
        )
        self._routes: Dict[Tuple[str, str], Handler] = {}
        self._lock = threading.Lock()
        self.route("GET", "/health", self._health)
        self.route("GET", "/transcript", self._transcript)
        self.route("POST", "/reset", self._reset)

    # -- registration ----------------------------------------------------
    def route(self, method: str, path: str, handler: Handler) -> None:
        self._routes[(method.upper(), path)] = handler

    # -- contract endpoints ----------------------------------------------
    def _health(self, request: Request) -> Response:
        return 200, {
            "service": self.name,
            "team": self.team,
            "spec_version": config.SPEC_VERSION,
        }, {}

    def _transcript(self, request: Request) -> Response:
        run_id = request.query.get("run_id")
        return 200, {"events": self.transcript.events(run_id)}, {}

    def _reset(self, request: Request) -> Response:
        self.transcript.reset()
        self.on_reset()
        return 200, {"reset": True, "service": self.name}, {}

    def on_reset(self) -> None:
        """Subclass hook: drop every piece of state the service holds.

        A half-reset leaves a session or a binding behind and the next run
        passes for the wrong reason.
        """

    # -- dispatch ---------------------------------------------------------
    def handle(self, request: Request) -> Response:
        handler = self._routes.get((request.method, request.path))
        if handler is None:
            if any(path == request.path for _, path in self._routes):
                return 405, {"error": "method_not_allowed"}, {}
            return 404, {"error": "not_found"}, {}
        if request.body_error is not None:
            return 400, {"error": request.body_error}, {}
        try:
            result = handler(request)
        except Exception:  # noqa: BLE001 - last line of defence
            # The traceback goes to our stderr, never into the response:
            # a leaked stack trace hands an attacker the file layout.
            traceback.print_exc(file=sys.stderr)
            return 500, {"error": "internal_error"}, {}
        return _normalise(result)

    # -- serving ----------------------------------------------------------
    def make_server(self, host: str, port: int) -> ThreadingHTTPServer:
        service = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "lab1-%s" % service.name
            sys_version = ""

            def do_GET(self) -> None:  # noqa: N802 - required name
                self._dispatch("GET")

            def do_POST(self) -> None:  # noqa: N802 - required name
                self._dispatch("POST")

            def _dispatch(self, method: str) -> None:
                parsed = urlparse(self.path)
                path = parsed.path
                if service.base_path and path.startswith(service.base_path):
                    path = path[len(service.base_path):] or "/"
                query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                headers = {k.lower(): v for k, v in self.headers.items()}
                body, body_error = self._read_body()
                request = Request(
                    method=method,
                    path=path.rstrip("/") or "/",
                    query=query,
                    headers=headers,
                    body=body,
                    body_error=body_error,
                    client_ip=self.client_address[0],
                )
                status, payload, extra = service.handle(request)
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                for key, value in extra.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

            def _read_body(self) -> Tuple[Any, Optional[str]]:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return None, "invalid_request"
                if length <= 0:
                    return None, None
                if length > MAX_BODY_BYTES:
                    return None, "request_too_large"
                raw = self.rfile.read(length)
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return None, "invalid_json"
                if not isinstance(parsed, dict):
                    return None, "invalid_json"
                return parsed, None

            def log_message(self, fmt: str, *args: Any) -> None:
                # One quiet line, and never the query string: URLs are the
                # classic place a secret ends up in a log file.
                if config.bool_setting("LAB1_QUIET_LOG", False):
                    return
                sys.stderr.write(
                    "[%s] %s %s\n"
                    % (service.name, self.command, urlparse(self.path).path)
                )

        return ThreadingHTTPServer((host, port), _Handler)

    def run(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        host = host or config.bind_host()
        port = port if port is not None else config.port_for(self.name)
        server = self.make_server(host, port)
        sys.stderr.write(
            "[%s] listening on %s:%d (team %s)\n" % (self.name, host, port, self.team)
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


def _normalise_base(value: Optional[str]) -> str:
    """`/team/verifier/` -> `/team/verifier`; anything empty -> ``."""
    if not value:
        return ""
    return "/" + value.strip().strip("/")


def _normalise(result: Any) -> Response:
    if isinstance(result, tuple) and len(result) == 3:
        return result
    if isinstance(result, tuple) and len(result) == 2:
        return result[0], result[1], {}
    raise TypeError("handler must return (status, body[, headers])")
