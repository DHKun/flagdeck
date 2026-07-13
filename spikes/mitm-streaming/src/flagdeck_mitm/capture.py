"""Bounded, ordered body capture for mitmproxy's synchronous stream callback.

The callback observes semantic HTTP body bytes.  Its chunk boundaries have no
wire-format meaning and are deliberately absent from the persisted contract.
"""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final


class CaptureMode(StrEnum):
    """Failure policy applied by the synchronous transform."""

    PASS_THROUGH = "pass-through"
    EVIDENCE_STRICT = "evidence-strict"


class BodyState(StrEnum):
    """Body completeness states shared with the FlagDeck data model."""

    COMPLETE = "complete"
    STREAMED_COMPLETE = "streamed_complete"
    TRUNCATED = "truncated"
    MISSING = "missing"
    CAPTURE_FAILED = "capture_failed"


class FaultKind(StrEnum):
    """Deterministic R0-only writer faults."""

    NONE = "none"
    ENOSPC = "enospc"
    WRITER_CRASH = "writer_crash"
    HASH_FAILURE = "hash_failure"


@dataclass(frozen=True, slots=True)
class FaultPlan:
    """Fault injection configuration used by unit and integration gates."""

    kind: FaultKind = FaultKind.NONE
    fail_after_bytes: int | None = None
    write_delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.fail_after_bytes is not None and self.fail_after_bytes < 0:
            raise ValueError("fail_after_bytes must be non-negative")
        if self.write_delay_seconds < 0:
            raise ValueError("write_delay_seconds must be non-negative")


@dataclass(frozen=True, slots=True)
class CaptureResult:
    """A point-in-time capture result safe for JSON serialization."""

    flow_id: str
    direction: str
    mode: str
    body_state: str
    declared_length: int | None
    observed_bytes: int
    captured_bytes: int
    forwarded_bytes: int
    frame_count: int
    sha256: str | None
    artifact_path: str | None
    partial_sha256: str | None
    partial_path: str | None
    content_encoding: str | None
    representation_kind: str
    terminal_reason: str | None
    failure_reason: str | None
    queue_capacity_bytes: int
    queue_capacity_frames: int
    enqueue_timeout_seconds: float
    queue_peak_bytes: int
    queue_peak_frames: int
    queue_wait_seconds: float
    queue_max_wait_seconds: float
    started_monotonic: float
    finished_monotonic: float | None
    duration_seconds: float | None
    terminal: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StrictCaptureError(RuntimeError):
    """Raised to halt mitmproxy forwarding after strict evidence failure."""


class _QueueAborted(RuntimeError):
    pass


@dataclass(slots=True)
class _Frame:
    data: bytes | None
    ack: threading.Event
    error: BaseException | None = None

    @property
    def size(self) -> int:
        return 0 if self.data is None else len(self.data)


class _BoundedFrameQueue:
    """A queue bounded simultaneously by payload bytes and frame count."""

    def __init__(self, max_bytes: int, max_frames: int) -> None:
        if max_bytes <= 0 or max_frames <= 0:
            raise ValueError("queue bounds must be positive")
        self.max_bytes = max_bytes
        self.max_frames = max_frames
        self._frames: deque[_Frame] = deque()
        self._bytes = 0
        self._peak_bytes = 0
        self._peak_frames = 0
        self._abort_error: BaseException | None = None
        self._condition = threading.Condition()

    @property
    def peaks(self) -> tuple[int, int]:
        with self._condition:
            return self._peak_bytes, self._peak_frames

    def put(self, frame: _Frame, timeout: float | None) -> bool:
        """Insert a frame, returning False when capacity cannot be obtained."""

        if frame.size > self.max_bytes:
            return False
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while True:
                if self._abort_error is not None:
                    frame.error = self._abort_error
                    frame.ack.set()
                    return False
                has_frame_room = len(self._frames) < self.max_frames
                has_byte_room = self._bytes + frame.size <= self.max_bytes
                if has_frame_room and has_byte_room:
                    self._frames.append(frame)
                    self._bytes += frame.size
                    self._peak_bytes = max(self._peak_bytes, self._bytes)
                    self._peak_frames = max(self._peak_frames, len(self._frames))
                    self._condition.notify_all()
                    return True
                if timeout == 0:
                    return False
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self._condition.wait(remaining)

    def get(self) -> _Frame:
        with self._condition:
            while not self._frames:
                if self._abort_error is not None:
                    raise _QueueAborted(str(self._abort_error)) from self._abort_error
                self._condition.wait()
            frame = self._frames.popleft()
            self._bytes -= frame.size
            self._condition.notify_all()
            return frame

    def abort(self, error: BaseException) -> None:
        with self._condition:
            if self._abort_error is None:
                self._abort_error = error
            while self._frames:
                frame = self._frames.popleft()
                self._bytes -= frame.size
                frame.error = self._abort_error
                frame.ack.set()
            self._condition.notify_all()


_END: Final[None] = None


class StreamCapture:
    """Capture one request or response body through a bounded writer queue.

    ``transform`` is designed to be assigned directly to ``Message.stream``.
    Non-empty input is always returned byte-for-byte when pass-through mode is
    selected.  Strict mode returns a chunk only after the writer acknowledges
    that complete chunk.
    """

    def __init__(
        self,
        *,
        capture_root: Path,
        flow_id: str,
        direction: str,
        mode: CaptureMode = CaptureMode.PASS_THROUGH,
        declared_length: int | None = None,
        content_encoding: str | None = None,
        queue_capacity_bytes: int = 4 * 1024 * 1024,
        queue_capacity_frames: int = 64,
        enqueue_timeout_seconds: float = 0.25,
        ack_timeout_seconds: float = 5.0,
        fault_plan: FaultPlan | None = None,
        on_terminal: Callable[[], None] | None = None,
    ) -> None:
        if direction not in {"request", "response"}:
            raise ValueError("direction must be request or response")
        if declared_length is not None and declared_length < 0:
            raise ValueError("declared_length must be non-negative")
        if ack_timeout_seconds <= 0 or enqueue_timeout_seconds < 0:
            raise ValueError("capture timeouts are invalid")

        self.capture_root = Path(capture_root)
        self.flow_id = flow_id
        self.direction = direction
        self.mode = mode
        self.declared_length = declared_length
        self.content_encoding = content_encoding
        self.enqueue_timeout_seconds = enqueue_timeout_seconds
        self.ack_timeout_seconds = ack_timeout_seconds
        self.fault_plan = fault_plan or FaultPlan()
        self._on_terminal = on_terminal

        self._queue = _BoundedFrameQueue(queue_capacity_bytes, queue_capacity_frames)
        self._queue_capacity_bytes = queue_capacity_bytes
        self._queue_capacity_frames = queue_capacity_frames
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._finished: float | None = None
        self._observed_bytes = 0
        self._captured_bytes = 0
        self._forwarded_bytes = 0
        self._frame_count = 0
        self._queue_wait_seconds = 0.0
        self._queue_max_wait_seconds = 0.0
        self._sha256: str | None = None
        self._artifact_path: Path | None = None
        self._partial_sha256: str | None = None
        self._partial_path: Path | None = None
        self._failure_reason: str | None = None
        self._terminal_reason: str | None = None
        self._body_state = BodyState.MISSING
        self._requested_terminal: BodyState | None = None
        self._end_started = False
        self._terminal = False
        self._released = False

        self._staging_dir = self.capture_root / "staging"
        self._artifact_dir = self.capture_root / "artifacts"
        self._failed_dir = self.capture_root / "failed"
        for directory in (
            self.capture_root,
            self._staging_dir,
            self._artifact_dir,
            self._failed_dir,
        ):
            self._ensure_private_directory(directory)

        token = secrets.token_hex(16)
        self._staging_path = self._staging_dir / f"capture-{token}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        self._fd = os.open(self._staging_path, flags, 0o600)
        os.chmod(self._staging_path, 0o600)

        self._writer_done = threading.Event()
        self._writer = threading.Thread(
            target=self._writer_loop,
            name=f"flagdeck-capture-{direction}-{token[:8]}",
            daemon=False,
        )
        self._writer.start()

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"capture path is not a real directory: {path}")
        os.chmod(path, 0o700)

    def transform(self, chunk: bytes) -> bytes:
        """Synchronous mitmproxy stream transform."""

        if not isinstance(chunk, bytes):
            raise TypeError("stream chunks must be bytes")
        if not chunk:
            self.finish()
            return b""

        with self._lock:
            self._observed_bytes += len(chunk)
            self._frame_count += 1
            failed = self._failure_reason is not None
            ended = self._end_started

        if ended:
            return self._handle_unavailable_chunk(chunk, "chunk_after_end")
        if failed:
            return self._handle_unavailable_chunk(chunk, "capture_already_failed")

        frame = _Frame(data=chunk, ack=threading.Event())
        queue_timeout = (
            self.enqueue_timeout_seconds
            if self.mode is CaptureMode.PASS_THROUGH
            else self.ack_timeout_seconds
        )
        wait_started = time.monotonic()
        enqueued = self._queue.put(frame, queue_timeout)
        waited = time.monotonic() - wait_started
        with self._lock:
            self._queue_wait_seconds += waited
            self._queue_max_wait_seconds = max(self._queue_max_wait_seconds, waited)
        if not enqueued:
            reason = "queue_full" if frame.error is None else "writer_unavailable"
            self._fail(reason)
            return self._handle_unavailable_chunk(chunk, reason)

        if self.mode is CaptureMode.PASS_THROUGH:
            with self._lock:
                self._forwarded_bytes += len(chunk)
            return chunk

        try:
            self._wait_for_ack(frame, "chunk_ack_timeout")
        except StrictCaptureError:
            return b""
        with self._lock:
            self._forwarded_bytes += len(chunk)
        return chunk

    def _handle_unavailable_chunk(self, chunk: bytes, reason: str) -> bytes:
        if self.mode is CaptureMode.PASS_THROUGH:
            with self._lock:
                self._forwarded_bytes += len(chunk)
            return chunk
        return b""

    def _wait_for_ack(self, frame: _Frame, timeout_reason: str) -> None:
        if not frame.ack.wait(self.ack_timeout_seconds):
            self._fail(timeout_reason)
            raise StrictCaptureError(
                f"strict capture stopped {self.direction} forwarding: {timeout_reason}"
            )
        if frame.error is not None:
            self._fail(self._describe_error(frame.error))
            raise StrictCaptureError(
                f"strict capture stopped {self.direction} forwarding: "
                f"{self._describe_error(frame.error)}"
            ) from frame.error

    def finish(
        self,
        *,
        terminal_state: BodyState | None = None,
        reason: str | None = None,
    ) -> CaptureResult:
        """Send the explicit end frame and wait for a durable terminal result."""

        with self._lock:
            if self._terminal:
                return self._result_locked()
            if terminal_state is not None:
                self._requested_terminal = terminal_state
            if reason:
                self._terminal_reason = reason
            if (
                reason
                and self._failure_reason is None
                and terminal_state is BodyState.CAPTURE_FAILED
            ):
                self._failure_reason = reason
            already_started = self._end_started
            self._end_started = True
            failed = self._failure_reason is not None

        if failed:
            self._queue.abort(RuntimeError(self._failure_reason or "capture_failed"))
        elif not already_started:
            frame = _Frame(data=_END, ack=threading.Event())
            if not self._queue.put(frame, self.ack_timeout_seconds):
                self._fail("end_queue_timeout")
            elif not frame.ack.wait(self.ack_timeout_seconds):
                self._fail("end_ack_timeout")
            elif frame.error is not None:
                self._fail(self._describe_error(frame.error))

        if not self._writer_done.wait(self.ack_timeout_seconds):
            self._fail("writer_shutdown_timeout")
            self._writer_done.wait(self.ack_timeout_seconds)

        with self._lock:
            if not self._terminal:
                self._terminal = True
                self._finished = time.monotonic()
                if self._failure_reason is not None:
                    self._body_state = BodyState.CAPTURE_FAILED
                elif self._requested_terminal is not None:
                    self._body_state = self._requested_terminal
                elif self.declared_length is not None and (
                    self._observed_bytes != self.declared_length
                ):
                    self._body_state = BodyState.TRUNCATED
                elif self._observed_bytes == 0:
                    self._body_state = BodyState.MISSING
                else:
                    self._body_state = BodyState.STREAMED_COMPLETE
                self._release_once_locked()
            result = self._result_locked()

        if (
            self.mode is CaptureMode.EVIDENCE_STRICT
            and result.body_state == BodyState.CAPTURE_FAILED
        ):
            raise StrictCaptureError(
                f"strict capture failed while finalizing {self.direction}: {result.failure_reason}"
            )
        return result

    def abort(self, reason: str = "connection_truncated") -> CaptureResult:
        """Durably commit an observed prefix as a truncated body."""

        return self.finish(terminal_state=BodyState.TRUNCATED, reason=reason)

    def result(self) -> CaptureResult:
        with self._lock:
            return self._result_locked()

    def _result_locked(self) -> CaptureResult:
        peak_bytes, peak_frames = self._queue.peaks
        duration = None if self._finished is None else self._finished - self._started
        return CaptureResult(
            flow_id=self.flow_id,
            direction=self.direction,
            mode=self.mode.value,
            body_state=self._body_state.value,
            declared_length=self.declared_length,
            observed_bytes=self._observed_bytes,
            captured_bytes=self._captured_bytes,
            forwarded_bytes=self._forwarded_bytes,
            frame_count=self._frame_count,
            sha256=self._sha256,
            artifact_path=str(self._artifact_path) if self._artifact_path else None,
            partial_sha256=self._partial_sha256,
            partial_path=str(self._partial_path) if self._partial_path else None,
            content_encoding=self.content_encoding,
            representation_kind="semantic",
            terminal_reason=self._terminal_reason,
            failure_reason=self._failure_reason,
            queue_capacity_bytes=self._queue_capacity_bytes,
            queue_capacity_frames=self._queue_capacity_frames,
            enqueue_timeout_seconds=self.enqueue_timeout_seconds,
            queue_peak_bytes=peak_bytes,
            queue_peak_frames=peak_frames,
            queue_wait_seconds=self._queue_wait_seconds,
            queue_max_wait_seconds=self._queue_max_wait_seconds,
            started_monotonic=self._started,
            finished_monotonic=self._finished,
            duration_seconds=duration,
            terminal=self._terminal,
        )

    def _fail(self, reason: str) -> None:
        with self._lock:
            if self._failure_reason is None:
                self._failure_reason = reason
                self._body_state = BodyState.CAPTURE_FAILED
        self._queue.abort(RuntimeError(reason))

    def _writer_loop(self) -> None:
        digest = hashlib.sha256()
        bytes_written = 0
        file_obj = os.fdopen(self._fd, "wb", buffering=0)
        try:
            while True:
                frame = self._queue.get()
                if frame.data is _END:
                    file_obj.flush()
                    os.fsync(file_obj.fileno())
                    file_obj.close()
                    if self.fault_plan.kind is FaultKind.HASH_FAILURE:
                        raise RuntimeError("injected hash failure")
                    body_hash = digest.hexdigest()
                    destination = self._artifact_dir / f"sha256-{body_hash}.body"
                    os.replace(self._staging_path, destination)
                    os.chmod(destination, 0o600)
                    self._fsync_directory(self._artifact_dir)
                    with self._lock:
                        self._captured_bytes = bytes_written
                        self._sha256 = body_hash
                        self._artifact_path = destination
                    frame.ack.set()
                    return

                try:
                    if self.fault_plan.write_delay_seconds:
                        time.sleep(self.fault_plan.write_delay_seconds)
                    bytes_written = self._write_frame(file_obj, digest, frame.data, bytes_written)
                    with self._lock:
                        self._captured_bytes = bytes_written
                    frame.ack.set()
                except BaseException as error:
                    frame.error = error
                    frame.ack.set()
                    raise
        except BaseException as error:
            self._record_writer_failure(error)
            actual_bytes = bytes_written if file_obj.closed else int(file_obj.tell())
            self._preserve_partial(file_obj, digest, actual_bytes)
        finally:
            if not file_obj.closed:
                file_obj.close()
            self._writer_done.set()

    def _write_frame(
        self,
        file_obj: Any,
        digest: Any,
        data: bytes,
        bytes_written: int,
    ) -> int:
        fail_after = self.fault_plan.fail_after_bytes
        if (
            self.fault_plan.kind is FaultKind.WRITER_CRASH
            and fail_after is not None
            and bytes_written >= fail_after
        ):
            raise RuntimeError("injected writer crash")

        if self.fault_plan.kind is FaultKind.ENOSPC and fail_after is not None:
            available = max(0, fail_after - bytes_written)
            prefix = data[:available]
            if prefix:
                self._write_all(file_obj, prefix)
                digest.update(prefix)
                bytes_written += len(prefix)
            if len(prefix) < len(data):
                raise OSError(errno.ENOSPC, "injected disk full")
            return bytes_written

        self._write_all(file_obj, data)
        digest.update(data)
        return bytes_written + len(data)

    @staticmethod
    def _write_all(file_obj: Any, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = file_obj.write(view)
            if written is None or written <= 0:
                raise OSError(errno.EIO, "short capture write")
            view = view[written:]

    def _record_writer_failure(self, error: BaseException) -> None:
        with self._lock:
            if self._failure_reason is None:
                self._failure_reason = self._describe_error(error)
            self._body_state = BodyState.CAPTURE_FAILED
        self._queue.abort(error)

    def _preserve_partial(self, file_obj: Any, digest: Any, bytes_written: int) -> None:
        try:
            if not file_obj.closed:
                file_obj.flush()
                os.fsync(file_obj.fileno())
                file_obj.close()
            if self._staging_path.exists():
                token = secrets.token_hex(16)
                destination = self._failed_dir / f"failed-{token}.partial"
                os.replace(self._staging_path, destination)
                os.chmod(destination, 0o600)
                self._fsync_directory(self._failed_dir)
                with self._lock:
                    self._partial_path = destination
                    self._partial_sha256 = digest.hexdigest()
                    self._captured_bytes = bytes_written
        except OSError as preserve_error:
            with self._lock:
                suffix = self._describe_error(preserve_error)
                current = self._failure_reason or "capture_failed"
                self._failure_reason = f"{current};partial_preserve:{suffix}"
            with suppress(OSError):
                self._staging_path.unlink(missing_ok=True)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _describe_error(error: BaseException) -> str:
        if isinstance(error, OSError) and error.errno is not None:
            return f"{type(error).__name__}:errno={error.errno}"
        message = str(error).strip().replace("\n", " ")
        return f"{type(error).__name__}:{message[:160]}" if message else type(error).__name__

    def _release_once_locked(self) -> None:
        if self._released:
            return
        self._released = True
        if self._on_terminal is not None:
            self._on_terminal()
