"""Cross-language contract checks for flagdeck.adapter.v1 fixtures."""

from __future__ import annotations

import json
import struct
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "r3" / "adapter-protocol" / "messages.json"
MAX_CONTROL_FRAME_BYTES = 1024 * 1024


def encode_frame(value: dict[str, Any]) -> bytes:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not 0 < len(payload) <= MAX_CONTROL_FRAME_BYTES:
        raise ValueError("control frame size is invalid")
    return struct.pack(">I", len(payload)) + payload


class AdapterProtocolContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_shared_messages_use_v1_json_rpc_contract(self) -> None:
        request = self.fixture["request"]
        self.assertEqual(self.fixture["protocol"], "flagdeck.adapter.v1")
        self.assertEqual(request["jsonrpc"], "2.0")
        self.assertEqual(
            set(request), {"jsonrpc", "id", "method", "metadata", "params"}
        )
        self.assertEqual(
            set(request["metadata"]),
            {
                "core_job_id",
                "adapter_job_id",
                "idempotency_key",
                "deadline_unix_millis",
            },
        )

    def test_frame_prefix_is_big_endian_and_exact(self) -> None:
        frame = encode_frame(self.fixture["notification"])
        size = struct.unpack(">I", frame[:4])[0]
        self.assertEqual(size, len(frame) - 4)
        self.assertEqual(json.loads(frame[4:]), self.fixture["notification"])

    def test_unknown_request_field_is_rejected_by_contract(self) -> None:
        allowed = {"jsonrpc", "id", "method", "metadata", "params"}
        self.assertNotEqual(set(self.fixture["invalid_unknown_request"]), allowed)


if __name__ == "__main__":
    unittest.main()
