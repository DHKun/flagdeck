"""One-shot private credential channel shared by the two R0 candidates."""

from __future__ import annotations

import os
import socket
import struct
import threading
from contextlib import suppress
from pathlib import Path
from types import TracebackType
from typing import Self

MAGIC = b"FDM1"
MAX_CREDENTIAL_BYTES = 1024


def encode_credential(username: str, password: str) -> bytearray:
    user = username.encode("ascii")
    secret = password.encode("ascii")
    if not 1 <= len(user) <= 64:
        raise ValueError("username length is invalid")
    if not 32 <= len(secret) <= 256:
        raise ValueError("password length is invalid")
    if not all(chr(byte).isalnum() or byte in b"_-" for byte in user):
        raise ValueError("username bytes are invalid")
    if not all(33 <= byte <= 126 and byte != ord("=") for byte in secret):
        raise ValueError("password bytes are invalid")
    payload = bytearray(MAGIC)
    payload.extend(len(user).to_bytes(2, "big"))
    payload.extend(len(secret).to_bytes(2, "big"))
    payload.extend(user)
    payload.extend(secret)
    if len(payload) > MAX_CREDENTIAL_BYTES:
        raise ValueError("credential payload exceeds limit")
    return payload


class OneShotCredentialServer:
    """Serve one credential over a filesystem AF_UNIX stream socket."""

    def __init__(self, path: Path, payload: bytearray) -> None:
        if not path.is_absolute():
            raise ValueError("credential socket path must be absolute")
        self.path = path
        self._payload = payload
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._done = threading.Event()
        self._error: BaseException | None = None
        self.peer_pid: int | None = None
        self.peer_uid: int | None = None
        self.peer_gid: int | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if self.path.exists():
            raise FileExistsError(self.path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        listener.listen(1)
        listener.settimeout(30)
        self._socket = listener
        self._thread = threading.Thread(target=self._serve, name="msf-credential-once")
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._zero_payload()
        self.path.unlink(missing_ok=True)
        with suppress(OSError):
            self.path.parent.rmdir()

    def wait_sent(self, timeout_seconds: float = 30.0) -> None:
        if not self._done.wait(timeout_seconds):
            raise TimeoutError("credential channel was not consumed")
        if self._error is not None:
            raise RuntimeError("credential channel failed") from self._error

    def _serve(self) -> None:
        try:
            if self._socket is None:
                raise RuntimeError("credential listener is unavailable")
            connection, _ = self._socket.accept()
            with connection:
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                self.peer_pid, self.peer_uid, self.peer_gid = struct.unpack("3i", peer)
                connection.sendall(memoryview(self._payload))
                connection.shutdown(socket.SHUT_WR)
        except BaseException as error:
            self._error = error
        finally:
            self._zero_payload()
            if self._socket is not None:
                self._socket.close()
            self.path.unlink(missing_ok=True)
            self._done.set()

    def _zero_payload(self) -> None:
        for index in range(len(self._payload)):
            self._payload[index] = 0
