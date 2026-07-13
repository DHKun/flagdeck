from __future__ import annotations

import pytest

from flagdeck_msf.rpc import (
    MsfRpcClient,
    ReplayPolicyError,
    RpcError,
    decode_rpc_value,
    rpc_error_message,
)


def client() -> MsfRpcClient:
    value = MsfRpcClient(
        host="127.0.0.1",
        port=55553,
        username="user",
        password="x" * 32,
    )
    value.token = "old-token"
    return value


def test_readonly_reauthenticates_and_replays_once(monkeypatch: pytest.MonkeyPatch) -> None:
    value = client()
    calls: list[list[object]] = []

    def fake_request(arguments: list[object]) -> object:
        calls.append(arguments)
        if arguments[0] == "auth.login":
            return {"result": "success", "token": "new-token"}
        if arguments[1] == "old-token":
            raise RpcError(500, "Invalid Authentication Token")
        return {"version": "6.4.135"}

    monkeypatch.setattr(value, "_rpc_request", fake_request)
    result = value.call_readonly("core.version")

    assert result == {"version": "6.4.135"}
    assert value.reauth_count == value.readonly_replay_count == 1
    assert [call[0] for call in calls] == ["core.version", "auth.login", "core.version"]


def test_execute_method_has_no_auto_replay() -> None:
    value = client()
    with pytest.raises(ReplayPolicyError):
        value.call_readonly("module.execute", "exploit", "multi/handler", {})
    assert value.reauth_count == value.readonly_replay_count == 0


def test_logout_supplies_authentication_and_rpc_argument_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = client()
    calls: list[list[object]] = []

    def fake_request(arguments: list[object]) -> object:
        calls.append(arguments)
        return {"result": "success"}

    monkeypatch.setattr(value, "_rpc_request", fake_request)
    assert value.logout() == {"result": "success"}
    assert calls == [["auth.logout", "old-token", "old-token"]]
    assert value.token is None


def test_authenticated_call_propagates_401(monkeypatch: pytest.MonkeyPatch) -> None:
    value = client()

    def fake(_: list[object]) -> object:
        raise RpcError(401, "expired")

    monkeypatch.setattr(value, "_rpc_request", fake)

    with pytest.raises(RpcError) as raised:
        value.call_authenticated("core.version")
    assert raised.value.invalid_authentication
    assert value.reauth_count == 0


def test_error_message_is_bounded_and_structured() -> None:
    assert rpc_error_message({"error_message": "Invalid Authentication Token"}) == (
        "Invalid Authentication Token"
    )
    assert rpc_error_message(["unexpected"]) == "RPC request failed"
    assert decode_rpc_value({b"result": b"success", b"nested": [b"value"]}) == {
        "result": "success",
        "nested": ["value"],
    }
