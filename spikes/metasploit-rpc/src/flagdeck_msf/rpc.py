"""Minimal standard MessagePack client with lifecycle TLS pinning."""

from __future__ import annotations

import hashlib
import http.client
import ssl
from collections.abc import Iterable
from typing import Any, Final

import msgpack  # type: ignore[import-untyped]

MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
IDEMPOTENT_READ_METHODS: Final[frozenset[str]] = frozenset(
    {
        "core.version",
        "module.info",
        "module.options",
        "module.search",
        "module.exploits",
        "module.auxiliary",
        "module.payloads",
        "module.encoders",
        "module.nops",
        "module.post",
        "module.evasion",
        "module.platforms",
        "module.architectures",
    }
)


class RpcError(RuntimeError):
    def __init__(self, status: int, message: str, payload: object | None = None) -> None:
        super().__init__(f"RPC status {status}: {message[:200]}")
        self.status = status
        self.message = message
        self.payload = payload

    @property
    def invalid_authentication(self) -> bool:
        lowered = self.message.lower()
        return self.status == 401 or "invalid authentication token" in lowered


class TlsPinError(RuntimeError):
    pass


class ReplayPolicyError(RuntimeError):
    pass


class MsfRpcClient:
    """RPC client that pins TLS and retries one idempotent read after re-login."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("RPC client host must be loopback")
        if not 0 < port <= 65535:
            raise ValueError("RPC port is invalid")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout_seconds = timeout_seconds
        self.token: str | None = None
        self.certificate_sha256: str | None = None
        self.reauth_count = 0
        self.readonly_replay_count = 0
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2

    def pin_current_endpoint(self) -> str:
        connection = self._new_connection()
        try:
            connection.connect()
            certificate = self._peer_certificate(connection)
        finally:
            connection.close()
        fingerprint = hashlib.sha256(certificate).hexdigest()
        if self.certificate_sha256 is not None and fingerprint != self.certificate_sha256:
            raise TlsPinError("RPC TLS certificate changed during lifecycle")
        self.certificate_sha256 = fingerprint
        return fingerprint

    def login(self) -> dict[str, Any]:
        response = self._rpc_request(["auth.login", self.username, self.password])
        result = require_mapping(response)
        token = result.get("token")
        if result.get("result") != "success" or not isinstance(token, str):
            raise RpcError(401, "login response was not successful", response)
        self.token = token
        return result

    def logout(self) -> dict[str, Any]:
        if self.token is None:
            raise RpcError(401, "client has no authentication token")
        result = require_mapping(self._authenticated_once("auth.logout", (self.token,)))
        if result.get("result") != "success":
            raise RpcError(500, "logout response was not successful", result)
        self.token = None
        return result

    def call_authenticated(self, method: str, *arguments: object) -> object:
        """Send exactly once; callers receive authentication errors directly."""

        return self._authenticated_once(method, arguments)

    def call_readonly(self, method: str, *arguments: object) -> object:
        """Retry one allow-listed idempotent read after one re-authentication."""

        if method not in IDEMPOTENT_READ_METHODS:
            raise ReplayPolicyError(f"automatic replay is not allowed for {method}")
        try:
            return self._authenticated_once(method, arguments)
        except RpcError as error:
            if not error.invalid_authentication:
                raise
        self.login()
        self.reauth_count += 1
        self.readonly_replay_count += 1
        return self._authenticated_once(method, arguments)

    def _authenticated_once(self, method: str, arguments: Iterable[object]) -> object:
        if self.token is None:
            raise RpcError(401, "client has no authentication token")
        return self._rpc_request([method, self.token, *arguments])

    def _rpc_request(self, arguments: list[object]) -> object:
        packed = msgpack.packb(arguments, use_bin_type=True)
        if not isinstance(packed, bytes):
            raise TypeError("MessagePack encoder returned a non-byte value")
        connection = self._new_connection()
        try:
            connection.connect()
            certificate = self._peer_certificate(connection)
            fingerprint = hashlib.sha256(certificate).hexdigest()
            if self.certificate_sha256 is None:
                raise TlsPinError("RPC endpoint has not been pinned")
            if fingerprint != self.certificate_sha256:
                raise TlsPinError("RPC TLS certificate changed during lifecycle")
            connection.request(
                "POST",
                "/api/",
                body=packed,
                headers={
                    "Content-Type": "binary/message-pack",
                    "Accept": "binary/message-pack",
                    "Connection": "close",
                    "User-Agent": "FlagDeck-R0/1",
                },
            )
            response = connection.getresponse()
            body = read_bounded(response, MAX_RESPONSE_BYTES)
            decoded: object | None = None
            if body:
                decoded = decode_rpc_value(msgpack.unpackb(body, raw=False, strict_map_key=False))
            if response.status != 200:
                raise RpcError(response.status, rpc_error_message(decoded), decoded)
            if decoded is None:
                raise RpcError(500, "empty RPC response")
            return decoded
        finally:
            connection.close()

    def _new_connection(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(
            self.host,
            self.port,
            timeout=self.timeout_seconds,
            context=self._context,
        )

    @staticmethod
    def _peer_certificate(connection: http.client.HTTPSConnection) -> bytes:
        if connection.sock is None:
            raise TlsPinError("TLS socket is unavailable")
        certificate = connection.sock.getpeercert(binary_form=True)
        if not isinstance(certificate, bytes) or not certificate:
            raise TlsPinError("TLS peer certificate is unavailable")
        return certificate


def read_bounded(response: http.client.HTTPResponse, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise RpcError(500, "RPC response exceeded size limit")
    return body


def require_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RpcError(500, "RPC response is not a map", value)
    return value


def rpc_error_message(value: object) -> str:
    if isinstance(value, dict):
        for key in ("error_message", "message", "error", "result"):
            message = value.get(key)
            if isinstance(message, str):
                return message
        error_class = value.get("error_class")
        if isinstance(error_class, str):
            return error_class
    return "RPC request failed"


def decode_rpc_value(value: object) -> object:
    """Normalize Ruby ASCII-8BIT MessagePack strings to Python text."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="surrogateescape")
    if isinstance(value, list):
        return [decode_rpc_value(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[object, object] = {}
        for key, item in value.items():
            normalized[decode_rpc_value(key)] = decode_rpc_value(item)
        return normalized
    return value
