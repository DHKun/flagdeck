from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest

from flagdeck_mitm.capture import (
    BodyState,
    CaptureMode,
    FaultKind,
    FaultPlan,
    StreamCapture,
    StrictCaptureError,
)


def new_capture(tmp_path: Path, **kwargs: object) -> StreamCapture:
    defaults: dict[str, object] = {
        "capture_root": tmp_path / "runtime",
        "flow_id": "flow-1",
        "direction": "request",
        "ack_timeout_seconds": 2.0,
    }
    defaults.update(kwargs)
    return StreamCapture(**defaults)  # type: ignore[arg-type]


def test_pass_through_commits_ordered_body(tmp_path: Path) -> None:
    capture = new_capture(tmp_path, declared_length=11)

    assert capture.transform(b"hello ") == b"hello "
    assert capture.transform(b"world") == b"world"
    assert capture.transform(b"") == b""

    result = capture.result()
    assert result.terminal
    assert result.body_state == BodyState.STREAMED_COMPLETE
    assert result.observed_bytes == result.captured_bytes == result.forwarded_bytes == 11
    assert result.sha256 == hashlib.sha256(b"hello world").hexdigest()
    assert result.artifact_path is not None
    artifact = Path(result.artifact_path)
    assert artifact.read_bytes() == b"hello world"
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert result.partial_path is None


def test_strict_mode_acknowledges_each_chunk(tmp_path: Path) -> None:
    capture = new_capture(
        tmp_path,
        direction="response",
        mode=CaptureMode.EVIDENCE_STRICT,
        content_encoding="br",
    )

    forwarded = b"".join(capture.transform(part) for part in (b"one", b"two", b"three"))
    result = capture.finish()

    assert forwarded == b"onetwothree"
    assert result.body_state == BodyState.STREAMED_COMPLETE
    assert result.content_encoding == "br"
    assert result.forwarded_bytes == result.captured_bytes == 11
    assert result.queue_peak_frames == 1


def test_declared_length_mismatch_is_truncated(tmp_path: Path) -> None:
    capture = new_capture(tmp_path, declared_length=20)
    capture.transform(b"prefix")

    result = capture.abort("client_connection_closed")

    assert result.body_state == BodyState.TRUNCATED
    assert result.terminal_reason == "client_connection_closed"
    assert result.sha256 == hashlib.sha256(b"prefix").hexdigest()
    assert result.observed_bytes == result.captured_bytes == 6


def test_empty_expected_body_is_missing(tmp_path: Path) -> None:
    capture = new_capture(tmp_path, declared_length=10)

    result = capture.finish()

    assert result.body_state == BodyState.TRUNCATED
    assert result.observed_bytes == 0


def test_queue_full_keeps_forwarding_and_marks_capture_failed(tmp_path: Path) -> None:
    capture = new_capture(
        tmp_path,
        queue_capacity_bytes=4096,
        queue_capacity_frames=1,
        enqueue_timeout_seconds=0.01,
        fault_plan=FaultPlan(write_delay_seconds=0.2),
    )
    chunks = [bytes([index]) * 4096 for index in range(12)]

    forwarded = b"".join(capture.transform(chunk) for chunk in chunks)
    result = capture.finish()

    assert forwarded == b"".join(chunks)
    assert result.body_state == BodyState.CAPTURE_FAILED
    assert result.failure_reason == "queue_full"
    assert result.forwarded_bytes == result.observed_bytes == len(forwarded)
    assert result.sha256 is None
    assert result.artifact_path is None
    assert result.queue_peak_bytes <= result.queue_capacity_bytes
    assert result.queue_peak_frames <= result.queue_capacity_frames


def test_enospc_preserves_partial_without_complete_artifact(tmp_path: Path) -> None:
    capture = new_capture(
        tmp_path,
        queue_capacity_bytes=64 * 1024,
        fault_plan=FaultPlan(kind=FaultKind.ENOSPC, fail_after_bytes=5000),
    )
    body = b"a" * 4096 + b"b" * 4096 + b"c" * 4096

    for offset in range(0, len(body), 4096):
        assert capture.transform(body[offset : offset + 4096]) == body[offset : offset + 4096]
    result = capture.finish()

    assert result.body_state == BodyState.CAPTURE_FAILED
    assert result.failure_reason == "OSError:errno=28"
    assert result.forwarded_bytes == len(body)
    assert result.captured_bytes == 5000
    assert result.artifact_path is None
    assert result.partial_path is not None
    partial = Path(result.partial_path)
    assert partial.read_bytes() == body[:5000]
    assert result.partial_sha256 == hashlib.sha256(body[:5000]).hexdigest()
    assert stat.S_IMODE(partial.stat().st_mode) == 0o600


def test_strict_writer_failure_stops_at_acknowledged_prefix(tmp_path: Path) -> None:
    capture = new_capture(
        tmp_path,
        mode=CaptureMode.EVIDENCE_STRICT,
        fault_plan=FaultPlan(kind=FaultKind.WRITER_CRASH, fail_after_bytes=4),
    )

    assert capture.transform(b"abcd") == b"abcd"
    assert capture.transform(b"efgh") == b""
    assert capture.transform(b"ijkl") == b""
    with pytest.raises(StrictCaptureError):
        capture.finish()

    result = capture.result()
    assert result.terminal
    assert result.body_state == BodyState.CAPTURE_FAILED
    assert result.forwarded_bytes == 4
    assert result.observed_bytes == 12
    assert result.captured_bytes == 4
    assert result.partial_path is not None
    assert Path(result.partial_path).read_bytes() == b"abcd"


def test_strict_finalize_failure_records_non_rollbackable_prefix(tmp_path: Path) -> None:
    capture = new_capture(
        tmp_path,
        mode=CaptureMode.EVIDENCE_STRICT,
        fault_plan=FaultPlan(kind=FaultKind.HASH_FAILURE),
    )

    assert capture.transform(b"already-forwarded") == b"already-forwarded"
    with pytest.raises(StrictCaptureError):
        capture.transform(b"")

    result = capture.result()
    assert result.body_state == BodyState.CAPTURE_FAILED
    assert result.forwarded_bytes == len(b"already-forwarded")
    assert result.partial_path is not None
    assert result.artifact_path is None


def test_terminal_callback_and_private_permissions(tmp_path: Path) -> None:
    released: list[bool] = []
    capture = new_capture(tmp_path, on_terminal=lambda: released.append(True))

    first = capture.finish()
    second = capture.finish()

    assert first == second
    assert released == [True]
    for name in ("runtime", "staging", "artifacts", "failed"):
        directory = tmp_path / "runtime" if name == "runtime" else tmp_path / "runtime" / name
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
