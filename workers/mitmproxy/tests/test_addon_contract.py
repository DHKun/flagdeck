from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from mitmproxy import http

from flagdeck_mitm.addon import (
    JsonlEventSink,
    _declared_length,
    _request_has_body,
    _response_has_body,
)


def flow_for(
    method: str,
    *,
    request_headers: dict[str, str] | None = None,
    response_status: int | None = None,
    response_headers: dict[str, str] | None = None,
) -> http.HTTPFlow:
    request = http.Request.make(method, "http://fixture.test/body")
    request.headers.pop("content-length", None)
    for name, value in (request_headers or {}).items():
        request.headers[name] = value
    if response_status is None:
        response = None
    else:
        response = http.Response.make(response_status, b"")
        response.headers.pop("content-length", None)
        for name, value in (response_headers or {}).items():
            response.headers[name] = value
    return cast(http.HTTPFlow, SimpleNamespace(request=request, response=response))


def test_request_body_detection_covers_declared_chunked_and_method() -> None:
    assert _request_has_body(flow_for("POST", request_headers={"Content-Length": "5"}))
    assert _request_has_body(flow_for("PUT", request_headers={"Transfer-Encoding": "chunked"}))
    assert _request_has_body(flow_for("PATCH"))
    assert not _request_has_body(flow_for("POST", request_headers={"Content-Length": "0"}))
    assert not _request_has_body(flow_for("GET"))
    assert not _request_has_body(flow_for("CONNECT"))


def test_response_body_detection_honors_http_no_body_cases() -> None:
    assert _response_has_body(flow_for("GET", response_status=200))
    assert _response_has_body(
        flow_for("GET", response_status=200, response_headers={"Content-Length": "10"})
    )
    assert not _response_has_body(
        flow_for("GET", response_status=200, response_headers={"Content-Length": "0"})
    )
    assert not _response_has_body(flow_for("HEAD", response_status=200))
    assert not _response_has_body(flow_for("GET", response_status=204))
    assert not _response_has_body(flow_for("GET", response_status=304))


def test_declared_length_is_defensive() -> None:
    assert _declared_length(http.Headers(content_length="12")) == 12
    assert _declared_length(http.Headers(content_length="-1")) is None
    assert _declared_length(http.Headers(content_length="invalid")) is None
    assert _declared_length(http.Headers()) is None


def test_jsonl_sink_is_private_ordered_and_parseable(tmp_path: Path) -> None:
    path = tmp_path / "private" / "events.jsonl"
    sink = JsonlEventSink(path)

    sink.emit({"event": "one", "value": cast(Any, "a")})
    sink.emit({"event": "two", "value": cast(Any, 2)})

    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [event["sequence"] for event in events] == [1, 2]
    assert [event["event"] for event in events] == ["one", "two"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
