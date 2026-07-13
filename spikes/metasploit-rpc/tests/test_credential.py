from __future__ import annotations

import socket
from pathlib import Path

from flagdeck_msf.credential import MAGIC, OneShotCredentialServer, encode_credential


def test_payload_and_one_shot_socket(tmp_path: Path) -> None:
    payload = encode_credential("fd_user", "x" * 32)
    expected = bytes(payload)
    path = (tmp_path / "private" / "credential.sock").resolve()

    with OneShotCredentialServer(path, payload) as server:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(path))
            received = bytearray()
            while chunk := client.recv(1024):
                received.extend(chunk)
        server.wait_sent()

    assert bytes(received) == expected
    assert received[:4] == MAGIC
    assert all(byte == 0 for byte in payload)
    assert not path.exists()
