from __future__ import annotations

import json
import tempfile
from pathlib import Path

from flagdeck_mitm.adapter import ADAPTER_PROTOCOL, MitmAdapter


def request(method: str, params: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": f"test-{method}",
        "method": method,
        "metadata": {
            "core_job_id": "test",
            "adapter_job_id": None,
            "idempotency_key": f"test-{method}",
            "deadline_unix_millis": "9999999999999",
        },
        "params": params or {},
    }


def test_initialize_describe_and_health_contract() -> None:
    with tempfile.TemporaryDirectory() as directory:
        adapter = MitmAdapter()
        initialized = adapter.dispatch(
            request(
                "initialize",
                {
                    "protocol": ADAPTER_PROTOCOL,
                    "project_id": "project-test",
                    "project_root": directory,
                },
            )
        )
        assert initialized["error"] is None
        described = adapter.dispatch(request("describe"))["result"]
        assert described["adapter_version"] == "1.0.0"
        assert described["capture_contract"]["queue_bytes"] == 4 * 1024 * 1024
        health = adapter.dispatch(request("health"))["result"]
        assert health == {
            "healthy": True,
            "proxy_running": False,
            "proxy_pid": None,
            "listen_port": None,
        }


def test_path_contract_rejects_escape() -> None:
    with tempfile.TemporaryDirectory() as directory:
        adapter = MitmAdapter()
        adapter.dispatch(
            request(
                "initialize",
                {
                    "protocol": ADAPTER_PROTOCOL,
                    "project_id": "project-test",
                    "project_root": directory,
                },
            )
        )
        response = adapter.dispatch(
            request(
                "start",
                {
                    "listen_host": "127.0.0.1",
                    "listen_port": 38001,
                    "confdir": "/tmp/escape",
                    "capture_root": str(Path(directory) / "capture"),
                    "events_file": str(Path(directory) / "events.jsonl"),
                },
            )
        )
        assert response["result"] is None
        assert response["error"]["code"] == -32040


def test_snapshot_resync_returns_only_new_http_metadata() -> None:
    with tempfile.TemporaryDirectory() as directory:
        events_file = Path(directory) / "events.jsonl"
        events_file.write_text(
            "\n".join(
                json.dumps(event)
                for event in [
                    {"sequence": 1, "event": "worker_ready"},
                    {"sequence": 2, "event": "http_message", "flow_id": "one"},
                    {"sequence": 3, "event": "body_capture_final"},
                    {"sequence": 4, "event": "http_message", "flow_id": "two"},
                ]
            )
            + "\n"
        )
        adapter = MitmAdapter()
        adapter.events_file = events_file
        snapshot = adapter.dispatch(request("snapshot", {"after_sequence": 2}))["result"]
        assert [event["flow_id"] for event in snapshot["events"]] == ["two"]
        assert snapshot["last_sequence"] == 4
        assert snapshot["has_more"] is False
