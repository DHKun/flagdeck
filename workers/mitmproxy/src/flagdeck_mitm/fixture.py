"""Loopback-only HTTP/HTTPS fixtures for the mitmproxy R0 gate."""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import random
import socket
import ssl
import threading
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, Self
from urllib.parse import parse_qs, urlsplit

import brotli  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

IO_CHUNK = 64 * 1024


@dataclass(frozen=True, slots=True)
class FixtureFile:
    name: str
    path: Path
    size: int
    sha256: str
    content_encoding: str | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "content_encoding": self.content_encoding,
        }


@dataclass(frozen=True, slots=True)
class FixtureCertificatePaths:
    ca_cert: Path
    server_cert: Path
    server_key: Path


class FixtureState:
    def __init__(self, files: dict[str, FixtureFile]) -> None:
        self.files = files
        self.uploads: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def record_upload(self, token: str, result: dict[str, Any]) -> None:
        with self.lock:
            self.uploads[token] = result


class _FixtureHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state: FixtureState) -> None:
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.fixture_state = state


class FixtureHandler(BaseHTTPRequestHandler):
    """Streaming fixture with explicit HTTP framing variants."""

    protocol_version = "HTTP/1.1"
    server_version = "FlagDeckFixture/1"
    sys_version = ""

    @property
    def state(self) -> FixtureState:
        return self.server.fixture_state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send_fixed(200, b"ok")
            return
        if not parsed.path.startswith("/body/"):
            self._send_fixed(404, b"missing")
            return
        name = parsed.path.removeprefix("/body/")
        fixture = self.state.files.get(name)
        if fixture is None:
            self._send_fixed(404, b"unknown fixture")
            return
        query = parse_qs(parsed.query)
        framing = query.get("framing", ["length"])[0]
        self._send_fixture(fixture, framing, query)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        token = query.get("token", ["untagged"])[0][:80]
        if parsed.path == "/early413":
            result = {
                "token": token,
                "received_bytes": 0,
                "sha256": hashlib.sha256().hexdigest(),
                "complete": False,
                "responded_before_body_complete": True,
            }
            self.state.record_upload(token, result)
            self.close_connection = True
            self._send_fixed(413, b"early", close=True)
            return
        if parsed.path != "/upload":
            self._send_fixed(404, b"missing")
            return

        digest = hashlib.sha256()
        received = 0
        expected = self._content_length()
        try:
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                received = self._read_chunked(digest)
                complete = True
            elif expected is not None:
                received = self._read_exact(expected, digest)
                complete = received == expected
            else:
                received = self._read_until_eof(digest)
                complete = True
        except (ConnectionError, OSError, ValueError):
            complete = False
        result = {
            "token": token,
            "received_bytes": received,
            "sha256": digest.hexdigest(),
            "complete": complete,
            "declared_length": expected,
            "transfer_encoding": self.headers.get("Transfer-Encoding"),
        }
        self.state.record_upload(token, result)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        try:
            self._send_fixed(200, encoded, content_type="application/json")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _content_length(self) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            value = int(raw, 10)
        except ValueError:
            return None
        return value if value >= 0 else None

    def _read_exact(self, expected: int, digest: Any) -> int:
        received = 0
        while received < expected:
            chunk = self.rfile.read(min(IO_CHUNK, expected - received))
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
        return received

    def _read_until_eof(self, digest: Any) -> int:
        received = 0
        while True:
            chunk = self.rfile.read(IO_CHUNK)
            if not chunk:
                return received
            digest.update(chunk)
            received += len(chunk)

    def _read_chunked(self, digest: Any) -> int:
        received = 0
        while True:
            line = self.rfile.readline(130)
            if not line or len(line) > 128 or not line.endswith(b"\r\n"):
                raise ValueError("invalid chunk size line")
            size_text = line[:-2].split(b";", 1)[0]
            size = int(size_text, 16)
            if size == 0:
                while True:
                    trailer = self.rfile.readline(8194)
                    if trailer in {b"\r\n", b""}:
                        return received
                    if len(trailer) > 8192:
                        raise ValueError("oversized trailer")
            remaining = size
            while remaining:
                chunk = self.rfile.read(min(IO_CHUNK, remaining))
                if not chunk:
                    raise ConnectionError("truncated chunk")
                digest.update(chunk)
                received += len(chunk)
                remaining -= len(chunk)
            if self.rfile.read(2) != b"\r\n":
                raise ValueError("missing chunk terminator")

    def _send_fixed(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/plain",
        close: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.wfile.flush()

    def _send_fixture(
        self, fixture: FixtureFile, framing: str, query: dict[str, list[str]]
    ) -> None:
        if framing not in {"length", "chunked", "close", "truncate"}:
            self._send_fixed(400, b"invalid framing")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        if fixture.content_encoding:
            self.send_header("Content-Encoding", fixture.content_encoding)
        if framing in {"length", "truncate"}:
            self.send_header("Content-Length", str(fixture.size))
        elif framing == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()

        cut = fixture.size
        if framing == "truncate":
            raw_cut = query.get("cut", [str(max(1, fixture.size // 4))])[0]
            cut = max(0, min(fixture.size - 1, int(raw_cut, 10)))
        sent = 0
        try:
            with fixture.path.open("rb", buffering=0) as source:
                while sent < cut:
                    chunk = source.read(min(IO_CHUNK, cut - sent))
                    if not chunk:
                        break
                    if framing == "chunked":
                        self.wfile.write(f"{len(chunk):x}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                    else:
                        self.wfile.write(chunk)
                    sent += len(chunk)
                if framing == "chunked":
                    self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        if framing == "truncate":
            self.close_connection = True
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()


class FixtureServers:
    """A plain and TLS fixture pair sharing immutable source files."""

    def __init__(
        self, files: dict[str, FixtureFile], certificate_paths: FixtureCertificatePaths
    ) -> None:
        self.state = FixtureState(files)
        self.http_server = _FixtureHttpServer(self.state)
        self.https_server = _FixtureHttpServer(self.state)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate_paths.server_cert, certificate_paths.server_key)
        self.https_server.socket = context.wrap_socket(self.https_server.socket, server_side=True)
        self._threads = [
            threading.Thread(target=self.http_server.serve_forever, name="fixture-http"),
            threading.Thread(target=self.https_server.serve_forever, name="fixture-https"),
        ]

    @property
    def http_port(self) -> int:
        return int(self.http_server.server_port)

    @property
    def https_port(self) -> int:
        return int(self.https_server.server_port)

    def __enter__(self) -> Self:
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        for server in (self.http_server, self.https_server):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=5)


def generate_fixture_files(
    root: Path, *, large_size: int, small_size: int
) -> dict[str, FixtureFile]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    large = _write_deterministic(root / "large.bin", large_size, seed=0xF1A6DEC)
    small = _write_deterministic(root / "small.bin", small_size, seed=0xC7F2026)
    gzip_file = _compress_gzip(root / "small.gzip", small)
    brotli_file = _compress_brotli(root / "small.br", small)
    return {item.name: item for item in (large, small, gzip_file, brotli_file)}


def generate_fixture_certificates(root: Path) -> FixtureCertificatePaths:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    now = dt.datetime.now(dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FlagDeck R0 Fixture CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=14))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=14))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths = FixtureCertificatePaths(
        ca_cert=root / "fixture-ca.pem",
        server_cert=root / "fixture-server.pem",
        server_key=root / "fixture-server-key.pem",
    )
    _write_private(paths.ca_cert, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(paths.server_cert, server_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        paths.server_key,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return paths


def hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb", buffering=0) as source:
        while chunk := source.read(IO_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _write_deterministic(path: Path, size: int, *, seed: int) -> FixtureFile:
    generator = random.Random(seed)
    digest = hashlib.sha256()
    remaining = size
    with _open_private(path) as output:
        while remaining:
            chunk = generator.randbytes(min(1024 * 1024, remaining))
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        output.flush()
        os.fsync(output.fileno())
    return FixtureFile(path.stem, path, size, digest.hexdigest())


def _compress_gzip(path: Path, source: FixtureFile) -> FixtureFile:
    with _open_private(path) as raw_output:
        with (
            gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as output,
            source.path.open("rb", buffering=0) as input_file,
        ):
            while chunk := input_file.read(IO_CHUNK):
                output.write(chunk)
        raw_output.flush()
        os.fsync(raw_output.fileno())
    size, digest = hash_file(path)
    return FixtureFile("gzip", path, size, digest, "gzip")


def _compress_brotli(path: Path, source: FixtureFile) -> FixtureFile:
    compressor = brotli.Compressor(quality=5)
    with _open_private(path) as output:
        with source.path.open("rb", buffering=0) as input_file:
            while chunk := input_file.read(IO_CHUNK):
                encoded = compressor.process(chunk)
                if encoded:
                    output.write(encoded)
        output.write(compressor.finish())
        output.flush()
        os.fsync(output.fileno())
    size, digest = hash_file(path)
    return FixtureFile("brotli", path, size, digest, "br")


def _open_private(path: Path) -> BinaryIO:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "wb", buffering=0)


def _write_private(path: Path, data: bytes) -> None:
    with _open_private(path) as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
