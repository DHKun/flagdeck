#!/usr/bin/env python3
"""Deterministic Loopback HTTP fixture for the FlagDeck R2 adapters."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], log_path: Path) -> None:
        super().__init__(address, FixtureHandler)
        self.log_path = log_path
        self.log_lock = threading.Lock()

    def record(self, value: dict[str, object]) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        with self.log_lock, self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "FlagDeckFixture/2.0"
    sys_version = ""

    def log_message(self, format_value: str, *args: object) -> None:
        del format_value, args

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle(send_body=False)

    def do_GET(self) -> None:  # noqa: N802
        self._handle(send_body=True)

    def _handle(self, *, send_body: bool) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/slow":
            time.sleep(30)
        status, content_type, body, extra_headers = self._response(parsed.path, query)
        fixture_server = self.server
        assert isinstance(fixture_server, FixtureServer)
        fixture_server.record(
            {
                "client": self.client_address[0],
                "host": self.headers.get("Host", ""),
                "method": self.command,
                "path": parsed.path,
                "query_keys": sorted(query),
            }
        )
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-FlagDeck-Fixture", "r2")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if send_body:
            self.wfile.write(encoded)

    @staticmethod
    def _response(
        path: str, query: dict[str, list[str]]
    ) -> tuple[int, str, str, list[tuple[str, str]]]:
        if path == "/":
            return (
                HTTPStatus.OK,
                "text/html; charset=utf-8",
                """<!doctype html><html><head><title>FlagDeck R2 Fixture</title></head>
               <body><a href="/admin">admin</a><a href="/api">api</a>
                <a href="/search">search</a></body></html>
""",
                [],
            )
        if path == "/admin":
            return HTTPStatus.OK, "text/plain", "admin-panel-r2", []
        if path == "/api":
            return HTTPStatus.OK, "application/json", '{"status":"ok","version":2}', []
        if path == "/redirect":
            return HTTPStatus.FOUND, "text/plain", "redirect", [("Location", "/admin")]
        if path == "/robots.txt":
            return HTTPStatus.OK, "text/plain", "User-agent: *\nDisallow: /admin\n", []
        if path == "/sitemap.xml":
            return (
                HTTPStatus.OK,
                "application/xml",
                "<urlset><url><loc>/api</loc></url></urlset>",
                [],
            )
        if path == "/search":
            visible = [name for name in ("debug", "id") if name in query]
            if visible:
                marker = "|".join(f"accepted:{name}" for name in visible)
                return HTTPStatus.OK, "text/plain", f"stable-search::{marker}", []
            return HTTPStatus.OK, "text/plain", "stable-search::baseline", []
        if path == "/slow":
            return HTTPStatus.OK, "text/plain", "slow-response-r3", []
        return HTTPStatus.NOT_FOUND, "text/plain", "fixture-not-found", []


def write_private_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--log-file", type=Path, required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    arguments.ready_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    arguments.log_file.touch(mode=0o600, exist_ok=False)
    server = FixtureServer(("127.0.0.1", 0), arguments.log_file)
    port = int(server.server_address[1])
    write_private_json(
        arguments.ready_file,
        {"host": "127.0.0.1", "port": port, "url": f"http://127.0.0.1:{port}"},
    )

    def stop(_signal: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    server.serve_forever(poll_interval=0.05)
    server.server_close()


if __name__ == "__main__":
    main()
