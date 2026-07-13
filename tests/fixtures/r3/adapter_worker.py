"""Deterministic flagdeck.adapter.v1 worker used by Rust host tests."""

from __future__ import annotations

import json
import os
import struct
import sys
from typing import BinaryIO, Any

MAX_CONTROL_FRAME_BYTES = 1024 * 1024


def read_frame(stream: BinaryIO) -> dict[str, Any] | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError("short frame header")
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > MAX_CONTROL_FRAME_BYTES:
        raise ValueError("invalid frame size")
    payload = stream.read(size)
    if len(payload) != size:
        raise ValueError("short frame payload")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("frame must contain an object")
    return value


def write_frame(stream: BinaryIO, value: dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack(">I", len(payload)))
    stream.write(payload)
    stream.flush()


def response(request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": result,
        "error": None,
    }


def main() -> int:
    adapter_fd = os.environ.get("FLAGDECK_ADAPTER_FD")
    stream = (
        os.fdopen(int(adapter_fd), "r+b", buffering=0)
        if adapter_fd is not None
        else sys.stdin.buffer
    )
    while request := read_frame(stream):
        method = request.get("method")
        if method == "crash":
            sys.stderr.write("fixture worker crashed\n")
            sys.stderr.flush()
            os._exit(23)
        if method == "stderr_flood":
            sys.stderr.buffer.write(b"F" * 131_072)
            sys.stderr.buffer.flush()
            write_frame(stream if adapter_fd is not None else sys.stdout.buffer, response(request, {"written": 131_072}))
            continue
        if method == "health":
            write_frame(stream if adapter_fd is not None else sys.stdout.buffer, response(request, {"healthy": True}))
            continue
        write_frame(
            stream if adapter_fd is not None else sys.stdout.buffer,
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": None,
                "error": {"code": -32601, "message": "method unavailable", "redacted_data": None},
            },
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
