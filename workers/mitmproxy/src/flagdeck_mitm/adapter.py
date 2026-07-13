"""Process-level flagdeck.adapter.v1 control server for mitmdump."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any, BinaryIO, Final

MAX_CONTROL_FRAME_BYTES: Final = 1024 * 1024
ADAPTER_PROTOCOL: Final = "flagdeck.adapter.v1"
MAX_STDERR_EVIDENCE: Final = 256 * 1024


class AdapterFailure(RuntimeError):
    """A bounded public adapter error."""


class _StderrCollector:
    def __init__(self, stream: IO[bytes]) -> None:
        self._stream = stream
        self._digest = hashlib.sha256()
        self._seen = 0
        self._hashed = 0
        self._thread = threading.Thread(target=self._run, name="mitmdump-stderr", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while chunk := self._stream.read(8192):
            self._seen += len(chunk)
            accepted = chunk[: max(0, MAX_STDERR_EVIDENCE - self._hashed)]
            self._digest.update(accepted)
            self._hashed += len(accepted)

    def result(self) -> dict[str, Any]:
        self._thread.join(timeout=1.0)
        return {
            "bytes_seen": self._seen,
            "bytes_hashed": self._hashed,
            "truncated": self._seen > self._hashed,
            "sha256": self._digest.hexdigest(),
        }


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            raise EOFError("short adapter frame")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream: BinaryIO) -> dict[str, Any] | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise AdapterFailure("short adapter frame header")
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > MAX_CONTROL_FRAME_BYTES:
        raise AdapterFailure("invalid adapter frame size")
    value = json.loads(_read_exact(stream, size))
    if not isinstance(value, dict):
        raise AdapterFailure("adapter frame must contain an object")
    return value


def write_frame(stream: BinaryIO, value: dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    if not payload or len(payload) > MAX_CONTROL_FRAME_BYTES:
        raise AdapterFailure("adapter response exceeded its bound")
    stream.write(struct.pack(">I", len(payload)))
    stream.write(payload)
    stream.flush()


def _response(request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": result, "error": None}


def _error(request: dict[str, Any], code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": None,
        "error": {"code": code, "message": message[:160], "redacted_data": None},
    }


def _absolute_path(value: Any, project_root: Path, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise AdapterFailure(f"{field} is required")
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise AdapterFailure(f"{field} must be absolute")
    resolved_parent = candidate.parent.resolve(strict=True)
    root = project_root.resolve(strict=True)
    if not resolved_parent.is_relative_to(root):
        raise AdapterFailure(f"{field} is outside the project")
    return resolved_parent / candidate.name


class MitmAdapter:
    def __init__(self) -> None:
        self.project_id: str | None = None
        self.project_root: Path | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.stderr: _StderrCollector | None = None
        self.listen_port: int | None = None
        self.events_file: Path | None = None

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("jsonrpc") != "2.0" or not isinstance(request.get("id"), str):
            return _error(request, -32600, "invalid Adapter v1 request")
        method = request.get("method")
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        try:
            if method == "initialize":
                return _response(request, self.initialize(params))
            if method == "describe":
                return _response(request, self.describe())
            if method == "health":
                return _response(request, self.health())
            if method == "start":
                return _response(request, self.start(params))
            if method == "snapshot":
                return _response(request, self.snapshot(params))
            if method in {"cancel", "shutdown"}:
                return _response(request, self.stop())
            return _error(request, -32601, "method unavailable")
        except (AdapterFailure, OSError, subprocess.SubprocessError) as error:
            return _error(request, -32040, str(error))

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        if params.get("protocol") != ADAPTER_PROTOCOL:
            raise AdapterFailure("unsupported adapter protocol")
        project_id = params.get("project_id")
        project_root = params.get("project_root")
        if not isinstance(project_id, str) or not project_id:
            raise AdapterFailure("project_id is required")
        if not isinstance(project_root, str) or not Path(project_root).is_absolute():
            raise AdapterFailure("project_root must be absolute")
        root = Path(project_root).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise AdapterFailure("project_root must be a real directory")
        self.project_id = project_id
        self.project_root = root
        return {"protocol": ADAPTER_PROTOCOL, "adapter_id": "flagdeck.mitmproxy"}

    @staticmethod
    def describe() -> dict[str, Any]:
        return {
            "adapter_id": "flagdeck.mitmproxy",
            "adapter_version": "1.0.0",
            "protocol": ADAPTER_PROTOCOL,
            "methods": [
                "initialize",
                "describe",
                "health",
                "start",
                "snapshot",
                "cancel",
                "shutdown",
            ],
            "capture_contract": {
                "queue_bytes": 4 * 1024 * 1024,
                "queue_frames": 256,
                "pass_through_timeout_seconds": 0.25,
                "strict_ack_timeout_seconds": 5.0,
                "max_active_captures": 8,
                "representation_kind": "semantic",
            },
        }

    def health(self) -> dict[str, Any]:
        running = self.process is not None and self.process.poll() is None
        return {
            "healthy": self.project_id is not None,
            "proxy_running": running,
            "proxy_pid": self.process.pid if running and self.process is not None else None,
            "listen_port": self.listen_port if running else None,
        }

    def start(self, params: dict[str, Any]) -> dict[str, Any]:
        if self.project_id is None or self.project_root is None:
            raise AdapterFailure("adapter is not initialized")
        if self.process is not None and self.process.poll() is None:
            raise AdapterFailure("proxy session is already active")
        listen_host = params.get("listen_host")
        listen_port = params.get("listen_port")
        mode = params.get("capture_mode", "pass-through")
        ssl_insecure = params.get("ssl_insecure", False)
        if listen_host != "127.0.0.1" or not isinstance(listen_port, int):
            raise AdapterFailure("proxy listener must use dynamic loopback")
        if not 1 <= listen_port <= 65535 or mode not in {"pass-through", "evidence-strict"}:
            raise AdapterFailure("proxy start parameters are invalid")
        if not isinstance(ssl_insecure, bool):
            raise AdapterFailure("ssl_insecure must be boolean")
        confdir = _absolute_path(params.get("confdir"), self.project_root, "confdir")
        capture_root = _absolute_path(params.get("capture_root"), self.project_root, "capture_root")
        events_file = _absolute_path(params.get("events_file"), self.project_root, "events_file")
        addon_script = Path(__file__).resolve().parents[2] / "flagdeck_worker_addon.py"
        mitmdump = Path(__file__).resolve().parents[2] / ".venv/bin/mitmdump"
        if not addon_script.is_file() or not mitmdump.is_file():
            raise AdapterFailure("mitmproxy worker installation is incomplete")
        for directory in [confdir, capture_root]:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        if events_file.exists():
            raise AdapterFailure("events_file must be unique per session")
        command = [
            str(mitmdump),
            "--quiet",
            "--listen-host",
            listen_host,
            "--listen-port",
            str(listen_port),
            "--set",
            f"confdir={confdir}",
            "--set",
            "store_streamed_bodies=false",
            "--set",
            f"ssl_insecure={'true' if ssl_insecure else 'false'}",
            "--set",
            f"flagdeck_capture_root={capture_root}",
            "--set",
            f"flagdeck_events_file={events_file}",
            "--set",
            f"flagdeck_capture_mode={mode}",
            "--set",
            "flagdeck_queue_bytes=4194304",
            "--set",
            "flagdeck_queue_frames=256",
            "--set",
            "flagdeck_enqueue_timeout=0.25",
            "--set",
            "flagdeck_ack_timeout=5.0",
            "--set",
            "flagdeck_max_active_captures=8",
            "-s",
            str(addon_script),
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        assert process.stderr is not None
        self.process = process
        self.stderr = _StderrCollector(process.stderr)
        self.listen_port = listen_port
        self.events_file = events_file
        self._wait_ready(events_file, listen_port)
        return {
            "state": "ready",
            "proxy_pid": process.pid,
            "listen_host": listen_host,
            "listen_port": listen_port,
            "events_file": str(events_file),
            "ssl_insecure": ssl_insecure,
        }

    def snapshot(self, params: dict[str, Any]) -> dict[str, Any]:
        after_sequence = params.get("after_sequence", 0)
        if not isinstance(after_sequence, int) or after_sequence < 0:
            raise AdapterFailure("after_sequence must be a non-negative integer")
        events_file = self.events_file
        if events_file is None or not events_file.is_file():
            return {"events": [], "last_sequence": after_sequence, "has_more": False}
        events: list[dict[str, Any]] = []
        last_sequence = after_sequence
        encoded_bytes = 0
        has_more = False
        with events_file.open("rb") as stream:
            for raw_line in stream:
                if len(raw_line) > MAX_CONTROL_FRAME_BYTES:
                    raise AdapterFailure("event line exceeded its control bound")
                event = json.loads(raw_line)
                sequence = event.get("sequence") if isinstance(event, dict) else None
                if not isinstance(sequence, int) or sequence <= 0:
                    raise AdapterFailure("event sequence is invalid")
                if sequence <= after_sequence:
                    continue
                event_bytes = len(raw_line)
                if event.get("event") == "http_message":
                    if events and (len(events) >= 100 or encoded_bytes + event_bytes > 800_000):
                        has_more = True
                        break
                    if event_bytes > 900_000:
                        raise AdapterFailure("HTTP metadata event exceeded snapshot bound")
                    events.append(event)
                    encoded_bytes += event_bytes
                last_sequence = sequence
        return {
            "events": events,
            "last_sequence": last_sequence,
            "has_more": has_more,
        }

    def _wait_ready(self, events_file: Path, port: int) -> None:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if self.process is None or self.process.poll() is not None:
                raise AdapterFailure("mitmdump exited before readiness")
            event_ready = False
            if events_file.is_file():
                with events_file.open("rb") as stream:
                    event_ready = b'"event":"worker_ready"' in stream.read(MAX_CONTROL_FRAME_BYTES)
            if event_ready:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        return
                except OSError:
                    pass
            time.sleep(0.05)
        self.stop()
        raise AdapterFailure("mitmdump readiness deadline exceeded")

    def stop(self) -> dict[str, Any]:
        process = self.process
        if process is None:
            return {"state": "stopped", "cleanup_verified": True}
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
        evidence = self.stderr.result() if self.stderr is not None else None
        result = {
            "state": "stopped",
            "cleanup_verified": process.poll() is not None,
            "exit_code": process.returncode,
            "stderr_evidence": evidence,
        }
        self.process = None
        self.stderr = None
        self.listen_port = None
        self.events_file = None
        return result


def _control_stream() -> BinaryIO:
    raw_fd = os.environ.get("FLAGDECK_ADAPTER_FD")
    if raw_fd is None:
        raise AdapterFailure("FLAGDECK_ADAPTER_FD is required")
    descriptor = int(raw_fd)
    if descriptor < 3:
        raise AdapterFailure("adapter descriptor is invalid")
    return os.fdopen(descriptor, "r+b", buffering=0)


def main() -> int:
    adapter = MitmAdapter()
    try:
        with _control_stream() as stream:
            while request := read_frame(stream):
                write_frame(stream, adapter.dispatch(request))
    except (AdapterFailure, EOFError, json.JSONDecodeError, ValueError) as error:
        sys.stderr.write(f"adapter control failure: {type(error).__name__}\n")
        return 2
    finally:
        adapter.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
