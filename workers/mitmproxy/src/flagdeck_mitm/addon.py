"""mitmproxy addon wiring bounded stream captures to HTTP flow hooks."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol

from mitmproxy import connection, ctx, exceptions, http

from .capture import (
    BodyState,
    CaptureMode,
    CaptureResult,
    FaultKind,
    FaultPlan,
    StreamCapture,
    StrictCaptureError,
)

DEFAULT_QUEUE_BYTES = 4 * 1024 * 1024
DEFAULT_QUEUE_FRAMES = 256
DEFAULT_ENQUEUE_TIMEOUT_SECONDS = 0.25
DEFAULT_ACK_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_ACTIVE_CAPTURES = 8


class _CaptureHandle(Protocol):
    def transform(self, chunk: bytes) -> bytes: ...

    def finish(
        self,
        *,
        terminal_state: BodyState | None = None,
        reason: str | None = None,
    ) -> CaptureResult: ...

    def abort(self, reason: str = "connection_truncated") -> CaptureResult: ...

    def result(self) -> CaptureResult: ...


@dataclass(frozen=True, slots=True)
class AddonConfig:
    capture_root: Path
    events_file: Path
    mode: CaptureMode
    queue_bytes: int
    queue_frames: int
    enqueue_timeout_seconds: float
    ack_timeout_seconds: float
    max_active_captures: int
    fault_plan: FaultPlan


class JsonlEventSink:
    """Append-only private JSONL sink with an in-process sequence number."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ValueError("event parent must be a real directory")
        os.chmod(self.path.parent, 0o700)
        self._lock = threading.Lock()
        self._sequence = 0

    def emit(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._sequence += 1
            payload = {
                "sequence": self._sequence,
                "timestamp_unix_ns": time.time_ns(),
                **event,
            }
            encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC
            fd = os.open(self.path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short event write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)


class _RejectedCapture:
    """Bounded-admission fallback that still counts callback-visible bytes."""

    def __init__(
        self,
        *,
        flow_id: str,
        direction: str,
        mode: CaptureMode,
        declared_length: int | None,
        content_encoding: str | None,
        reason: str,
        queue_bytes: int,
        queue_frames: int,
        enqueue_timeout_seconds: float,
    ) -> None:
        self.flow_id = flow_id
        self.direction = direction
        self.mode = mode
        self.declared_length = declared_length
        self.content_encoding = content_encoding
        self.reason = reason
        self.queue_bytes = queue_bytes
        self.queue_frames = queue_frames
        self.enqueue_timeout_seconds = enqueue_timeout_seconds
        self.started = time.monotonic()
        self.finished: float | None = None
        self.observed = 0
        self.forwarded = 0
        self.frames = 0
        self.terminal_reason: str | None = None
        self._lock = threading.Lock()

    def transform(self, chunk: bytes) -> bytes:
        if not chunk:
            self.finish()
            return b""
        with self._lock:
            self.observed += len(chunk)
            self.frames += 1
            if self.mode is CaptureMode.PASS_THROUGH:
                self.forwarded += len(chunk)
                return chunk
        return b""

    def finish(
        self,
        *,
        terminal_state: BodyState | None = None,
        reason: str | None = None,
    ) -> CaptureResult:
        del terminal_state
        with self._lock:
            if reason:
                self.terminal_reason = reason
            if self.finished is None:
                self.finished = time.monotonic()
            result = self._result_locked()
        if self.mode is CaptureMode.EVIDENCE_STRICT:
            raise StrictCaptureError(
                f"strict capture failed while finalizing {self.direction}: {self.reason}"
            )
        return result

    def abort(self, reason: str = "connection_truncated") -> CaptureResult:
        return self.finish(reason=reason)

    def result(self) -> CaptureResult:
        with self._lock:
            return self._result_locked()

    def _result_locked(self) -> CaptureResult:
        return CaptureResult(
            flow_id=self.flow_id,
            direction=self.direction,
            mode=self.mode.value,
            body_state=BodyState.CAPTURE_FAILED.value,
            declared_length=self.declared_length,
            observed_bytes=self.observed,
            captured_bytes=0,
            forwarded_bytes=self.forwarded,
            frame_count=self.frames,
            sha256=None,
            artifact_path=None,
            partial_sha256=None,
            partial_path=None,
            content_encoding=self.content_encoding,
            representation_kind="semantic",
            terminal_reason=self.terminal_reason,
            failure_reason=self.reason,
            queue_capacity_bytes=self.queue_bytes,
            queue_capacity_frames=self.queue_frames,
            enqueue_timeout_seconds=self.enqueue_timeout_seconds,
            queue_peak_bytes=0,
            queue_peak_frames=0,
            queue_wait_seconds=0.0,
            queue_max_wait_seconds=0.0,
            started_monotonic=self.started,
            finished_monotonic=self.finished,
            duration_seconds=(None if self.finished is None else self.finished - self.started),
            terminal=self.finished is not None,
        )


class StreamingCaptureAddon:
    """Install independent request/response capture transforms per flow."""

    _OPTION_NAMES: ClassVar[set[str]] = {
        "flagdeck_capture_root",
        "flagdeck_events_file",
        "flagdeck_capture_mode",
        "flagdeck_queue_bytes",
        "flagdeck_queue_frames",
        "flagdeck_enqueue_timeout",
        "flagdeck_ack_timeout",
        "flagdeck_max_active_captures",
        "flagdeck_fault_kind",
        "flagdeck_fault_after_bytes",
        "flagdeck_write_delay",
    }

    def __init__(self) -> None:
        self._captures: dict[tuple[str, str], _CaptureHandle] = {}
        self._capture_clients: dict[tuple[str, str], str] = {}
        self._capture_messages: dict[tuple[str, str], dict[str, Any]] = {}
        self._message_emitted: set[tuple[str, str]] = set()
        self._captures_lock = threading.Lock()
        self._slots: threading.BoundedSemaphore | None = None
        self._sink: JsonlEventSink | None = None
        self._config_cache: AddonConfig | None = None

    def load(self, loader: Any) -> None:
        loader.add_option("flagdeck_capture_root", str, "", "Private body capture root.")
        loader.add_option("flagdeck_events_file", str, "", "Private JSONL evidence path.")
        loader.add_option(
            "flagdeck_capture_mode",
            str,
            CaptureMode.PASS_THROUGH.value,
            "Body evidence failure policy.",
            choices=tuple(mode.value for mode in CaptureMode),
        )
        loader.add_option(
            "flagdeck_queue_bytes", int, DEFAULT_QUEUE_BYTES, "Per-direction queue byte cap."
        )
        loader.add_option(
            "flagdeck_queue_frames", int, DEFAULT_QUEUE_FRAMES, "Per-direction queue frame cap."
        )
        loader.add_option(
            "flagdeck_enqueue_timeout",
            str,
            str(DEFAULT_ENQUEUE_TIMEOUT_SECONDS),
            "Pass-through queue backpressure timeout in seconds.",
        )
        loader.add_option(
            "flagdeck_ack_timeout",
            str,
            str(DEFAULT_ACK_TIMEOUT_SECONDS),
            "Strict writer ack and finalization timeout in seconds.",
        )
        loader.add_option(
            "flagdeck_max_active_captures",
            int,
            DEFAULT_MAX_ACTIVE_CAPTURES,
            "Global bound for dedicated body writer threads.",
        )
        loader.add_option(
            "flagdeck_fault_kind",
            str,
            FaultKind.NONE.value,
            "R0-only deterministic writer fault.",
            choices=tuple(kind.value for kind in FaultKind),
        )
        loader.add_option(
            "flagdeck_fault_after_bytes", int, -1, "R0 fault threshold; -1 disables it."
        )
        loader.add_option("flagdeck_write_delay", str, "0.0", "R0 writer delay per frame.")

    def configure(self, updated: set[str]) -> None:
        if updated & self._OPTION_NAMES:
            self._read_config()

    def running(self) -> None:
        config = self._read_config(require_paths=True)
        self._slots = threading.BoundedSemaphore(config.max_active_captures)
        self._sink = JsonlEventSink(config.events_file)
        self._config_cache = config
        self._sink.emit(
            {
                "event": "worker_ready",
                "listen_host_contract": "127.0.0.1",
                "mode": config.mode.value,
                "queue_bytes": config.queue_bytes,
                "queue_frames": config.queue_frames,
                "enqueue_timeout_seconds": config.enqueue_timeout_seconds,
                "ack_timeout_seconds": config.ack_timeout_seconds,
                "max_active_captures": config.max_active_captures,
                "store_streamed_bodies": bool(ctx.options.store_streamed_bodies),
            }
        )

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if _request_has_body(flow):
            capture = self._start_capture(flow, "request")
            flow.request.stream = capture.transform

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None and _response_has_body(flow):
            capture = self._start_capture(flow, "response")
            flow.response.stream = capture.transform

    def request(self, flow: http.HTTPFlow) -> None:
        if not self._finalize(flow, "request", "request"):
            self._emit_http_message(flow, "request", hook="request")

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._finalize(flow, "response", "response"):
            self._emit_http_message(flow, "response", hook="response")

    def error(self, flow: http.HTTPFlow) -> None:
        reason = "flow_error"
        if flow.error is not None:
            reason = f"flow_error:{flow.error.msg[:160]}"
        self._finalize(flow, "request", "error", truncated=True, reason=reason)
        self._finalize(flow, "response", "error", truncated=True, reason=reason)

    def client_disconnected(self, client: connection.Client) -> None:
        with self._captures_lock:
            keys = [
                key for key, client_id in self._capture_clients.items() if client_id == client.id
            ]
            pending = [
                (key, self._captures.pop(key), self._capture_messages.pop(key, None))
                for key in keys
                if key in self._captures
            ]
            for key in keys:
                self._capture_clients.pop(key, None)
        for _key, capture, message in pending:
            try:
                result = capture.abort("client_disconnected")
            except StrictCaptureError:
                result = capture.result()
            self._emit_result(result, hook="client_disconnected", message=message)

    def done(self) -> None:
        with self._captures_lock:
            pending = [
                (key, capture, self._capture_messages.pop(key, None))
                for key, capture in self._captures.items()
            ]
            self._captures.clear()
            self._capture_clients.clear()
        for _key, capture, message in pending:
            try:
                result = capture.abort("worker_shutdown")
            except StrictCaptureError:
                result = capture.result()
            self._emit_result(result, hook="done", message=message)
        if self._sink is not None:
            self._sink.emit({"event": "worker_done", "pending_captures": len(pending)})

    def _start_capture(self, flow: http.HTTPFlow, direction: str) -> _CaptureHandle:
        config = self._config_cache or self._read_config(require_paths=True)
        message = flow.request if direction == "request" else flow.response
        assert message is not None
        declared = _declared_length(message.headers)
        encoding = message.headers.get("content-encoding") or None
        key = (flow.id, direction)
        slot_acquired = self._slots is not None and self._slots.acquire(blocking=False)

        if slot_acquired:
            try:
                capture: _CaptureHandle = StreamCapture(
                    capture_root=config.capture_root,
                    flow_id=flow.id,
                    direction=direction,
                    mode=config.mode,
                    declared_length=declared,
                    content_encoding=encoding,
                    queue_capacity_bytes=config.queue_bytes,
                    queue_capacity_frames=config.queue_frames,
                    enqueue_timeout_seconds=config.enqueue_timeout_seconds,
                    ack_timeout_seconds=config.ack_timeout_seconds,
                    fault_plan=config.fault_plan,
                    on_terminal=self._release_slot,
                )
            except (OSError, ValueError) as error:
                self._release_slot()
                capture = self._rejected_capture(
                    flow, direction, f"capture_start:{type(error).__name__}", config
                )
        else:
            capture = self._rejected_capture(flow, direction, "active_capture_limit", config)

        with self._captures_lock:
            if key in self._captures:
                raise RuntimeError(f"duplicate capture key: {key}")
            self._captures[key] = capture
            self._capture_clients[key] = flow.client_conn.id
            self._capture_messages[key] = _message_payload(flow, direction)
        self._emit(
            {
                "event": "body_capture_started",
                "flow_id": flow.id,
                "direction": direction,
                "mode": config.mode.value,
                "declared_length": declared,
                "content_encoding": encoding,
                "representation_kind": "semantic",
            }
        )
        return capture

    @staticmethod
    def _rejected_capture(
        flow: http.HTTPFlow, direction: str, reason: str, config: AddonConfig
    ) -> _RejectedCapture:
        message = flow.request if direction == "request" else flow.response
        assert message is not None
        return _RejectedCapture(
            flow_id=flow.id,
            direction=direction,
            mode=config.mode,
            declared_length=_declared_length(message.headers),
            content_encoding=message.headers.get("content-encoding") or None,
            reason=reason,
            queue_bytes=config.queue_bytes,
            queue_frames=config.queue_frames,
            enqueue_timeout_seconds=config.enqueue_timeout_seconds,
        )

    def _finalize(
        self,
        flow: http.HTTPFlow,
        direction: str,
        hook: str,
        *,
        truncated: bool = False,
        reason: str | None = None,
    ) -> bool:
        with self._captures_lock:
            capture = self._captures.pop((flow.id, direction), None)
            self._capture_clients.pop((flow.id, direction), None)
            message = self._capture_messages.pop((flow.id, direction), None)
        if capture is None:
            return False
        try:
            result = capture.abort(reason or "flow_truncated") if truncated else capture.finish()
        except StrictCaptureError:
            result = capture.result()
        self._emit_result(result, hook=hook, message=message)
        return True

    def _emit_result(
        self, result: CaptureResult, *, hook: str, message: dict[str, Any] | None
    ) -> None:
        self._emit({"event": "body_capture_final", "terminal_hook": hook, **result.to_dict()})
        if message is not None:
            self._emit_message_payload(message, result=result, hook=hook)

    def _emit_http_message(self, flow: http.HTTPFlow, direction: str, *, hook: str) -> None:
        self._emit_message_payload(_message_payload(flow, direction), result=None, hook=hook)

    def _emit_message_payload(
        self, message: dict[str, Any], *, result: CaptureResult | None, hook: str
    ) -> None:
        key = (str(message["flow_id"]), str(message["direction"]))
        with self._captures_lock:
            if key in self._message_emitted:
                return
            self._message_emitted.add(key)
        body = (
            {
                "body_state": BodyState.MISSING.value,
                "declared_length": None,
                "actual_length": 0,
                "captured_length": 0,
                "content_encoding": None,
                "body_path": None,
                "body_sha256": None,
                "failure_reason": None,
            }
            if result is None
            else {
                "body_state": result.body_state,
                "declared_length": result.declared_length,
                "actual_length": result.observed_bytes,
                "captured_length": result.captured_bytes,
                "content_encoding": result.content_encoding,
                "body_path": result.artifact_path or result.partial_path,
                "body_sha256": result.sha256 or result.partial_sha256,
                "failure_reason": result.failure_reason,
            }
        )
        self._emit(
            {
                "event": "http_message",
                "terminal_hook": hook,
                **message,
                **body,
                "representation_kind": "semantic",
                "serializer_version": "mitmproxy.semantic/12.2.3",
            }
        )

    def _emit(self, event: dict[str, Any]) -> None:
        if self._sink is None:
            config = self._config_cache or self._read_config(require_paths=True)
            self._sink = JsonlEventSink(config.events_file)
        self._sink.emit(event)

    def _release_slot(self) -> None:
        if self._slots is not None:
            self._slots.release()

    def _read_config(self, *, require_paths: bool = False) -> AddonConfig:
        capture_root_text = str(getattr(ctx.options, "flagdeck_capture_root", ""))
        events_file_text = str(getattr(ctx.options, "flagdeck_events_file", ""))
        if require_paths and (not capture_root_text or not events_file_text):
            raise _options_error("flagdeck_capture_root and flagdeck_events_file are required")
        queue_bytes = int(ctx.options.flagdeck_queue_bytes)
        queue_frames = int(ctx.options.flagdeck_queue_frames)
        enqueue_timeout = float(ctx.options.flagdeck_enqueue_timeout)
        ack_timeout = float(ctx.options.flagdeck_ack_timeout)
        max_active = int(ctx.options.flagdeck_max_active_captures)
        delay = float(ctx.options.flagdeck_write_delay)
        fault_after_raw = int(ctx.options.flagdeck_fault_after_bytes)
        if queue_bytes <= 0 or queue_frames <= 0:
            raise _options_error("FlagDeck queue bounds must be positive")
        if enqueue_timeout < 0 or ack_timeout <= 0 or max_active <= 0:
            raise _options_error("FlagDeck timeout and active limit must be positive")
        if delay < 0 or fault_after_raw < -1:
            raise _options_error("FlagDeck fault values are invalid")
        try:
            mode = CaptureMode(str(ctx.options.flagdeck_capture_mode))
            fault_kind = FaultKind(str(ctx.options.flagdeck_fault_kind))
        except ValueError as error:
            raise _options_error(str(error)) from error
        fault_after = None if fault_after_raw == -1 else fault_after_raw
        if fault_kind in {FaultKind.ENOSPC, FaultKind.WRITER_CRASH} and fault_after is None:
            raise _options_error("selected writer fault requires a byte threshold")
        return AddonConfig(
            capture_root=Path(capture_root_text),
            events_file=Path(events_file_text),
            mode=mode,
            queue_bytes=queue_bytes,
            queue_frames=queue_frames,
            enqueue_timeout_seconds=enqueue_timeout,
            ack_timeout_seconds=ack_timeout,
            max_active_captures=max_active,
            fault_plan=FaultPlan(
                kind=fault_kind,
                fail_after_bytes=fault_after,
                write_delay_seconds=delay,
            ),
        )


def _declared_length(headers: http.Headers) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw, 10)
    except ValueError:
        return None
    return value if value >= 0 else None


def _options_error(message: str) -> exceptions.OptionsError:
    return exceptions.OptionsError(message)  # type: ignore[no-untyped-call]


def _request_has_body(flow: http.HTTPFlow) -> bool:
    request = flow.request
    if request.method.upper() == "CONNECT":
        return False
    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        return _declared_length(request.headers) not in {None, 0}
    if request.headers.get("transfer-encoding"):
        return True
    return request.method.upper() in {"POST", "PUT", "PATCH"}


def _response_has_body(flow: http.HTTPFlow) -> bool:
    response = flow.response
    if response is None:
        return False
    if flow.request.method.upper() == "HEAD":
        return False
    if 100 <= response.status_code < 200 or response.status_code in {204, 304}:
        return False
    raw_length = response.headers.get("content-length")
    if raw_length is not None:
        return _declared_length(response.headers) not in {None, 0}
    return True


def _ordered_headers(headers: http.Headers | None) -> list[dict[str, str]]:
    if headers is None:
        return []
    return [
        {
            "name": name.decode("latin-1", errors="replace"),
            "value": value.decode("latin-1", errors="replace"),
        }
        for name, value in headers.fields
    ]


def _ordered_values(values: Any) -> list[dict[str, str]]:
    try:
        fields = values.fields
    except (AttributeError, TypeError, ValueError):
        return []
    return [{"name": str(name), "value": str(value)} for name, value in fields]


def _connection_address(value: Any) -> str | None:
    address = getattr(value, "address", None)
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address) if address else None


def _message_payload(flow: http.HTTPFlow, direction: str) -> dict[str, Any]:
    request = flow.request
    response = flow.response
    message = request if direction == "request" else response
    assert message is not None
    host = request.pretty_host
    port = request.port
    default_port = 443 if request.scheme == "https" else 80
    authority = request.host_header or (host if port == default_port else f"{host}:{port}")
    duration_millis: int | None = None
    if direction == "response" and flow.response is not None:
        started = request.timestamp_start
        finished = flow.response.timestamp_end or flow.response.timestamp_start
        if started is not None and finished is not None and finished >= started:
            duration_millis = round((finished - started) * 1000)
    trailers = getattr(message, "trailers", None)
    tls_version = getattr(flow.server_conn, "tls_version", None)
    return {
        "flow_id": flow.id,
        "direction": direction,
        "method": request.method if direction == "request" else None,
        "status_code": response.status_code if direction == "response" and response else None,
        "scheme": request.scheme,
        "host": host,
        "port": port,
        "authority": authority,
        "path": request.path,
        "http_version": message.http_version,
        "headers": _ordered_headers(message.headers),
        "trailers": _ordered_headers(trailers),
        "query": _ordered_values(request.query),
        "form": [],
        "duration_millis": duration_millis,
        "connection": {
            "client_address": _connection_address(flow.client_conn),
            "server_address": _connection_address(flow.server_conn),
            "tls": bool(flow.server_conn.tls),
            "tls_version": tls_version,
            "certificate_sha256": None,
        },
    }
