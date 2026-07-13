"""Metasploit standard MessagePack/TLS lifecycle and credential-channel gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from .credential import OneShotCredentialServer, encode_credential
from .rpc import IDEMPOTENT_READ_METHODS, MsfRpcClient, ReplayPolicyError, RpcError, require_mapping

SPIKE_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
LAUNCHER = WORKSPACE_ROOT / "target" / "release" / "flagdeck-msf-credential-launcher"
MSFRPCD = Path("/opt/metasploit-framework/embedded/framework/msfrpcd")
MSGRPC = Path("/opt/metasploit-framework/embedded/framework/plugins/msgrpc.rb")
TOKEN_TIMEOUT_SECONDS = 2
TOKEN_IDLE_WAIT_SECONDS = 3.2
RPC_MODULE_TYPE = "auxiliary"
RPC_MODULE_NAME = "scanner/http/http_version"
SECRET_SCAN_FILE_LIMIT: Final = 64 * 1024 * 1024


class GateFailure(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    pid: int
    start_time_ticks: int
    executable: str
    argv: list[str]
    cgroup: str


@dataclass(frozen=True, slots=True)
class ListenerRecord:
    host: str
    port: int
    inode: str


class GateRunner:
    def __init__(self) -> None:
        self.protected_before: list[ProcessRecord] = []
        self.protected_after: list[ProcessRecord] = []
        self.candidates: list[dict[str, Any]] = []
        self.assertions: dict[str, bool] = {}

    def run(self, runtime_root: Path) -> dict[str, Any]:
        require_executable(LAUNCHER)
        require_executable(MSFRPCD)
        self.protected_before = snapshot_protected_processes()

        for channel in ("direct-socket", "systemd-load-credential"):
            self.candidates.append(self._run_candidate(runtime_root, channel))

        self.protected_after = snapshot_protected_processes()
        self._evaluate_assertions(runtime_root)
        failed = sorted(name for name, passed in self.assertions.items() if not passed)
        if failed:
            raise GateFailure(f"Metasploit assertions failed: {failed}")

        return {
            "schema": "flagdeck.metasploit-rpc-r0.v1",
            "status": "PASS",
            "generated_unix_ns": time.time_ns(),
            "environment": {
                "systemd": command_text(["systemctl", "--version"]).splitlines()[0],
                "rpm": command_text(["rpm", "-q", "metasploit-framework"]),
                "launcher_sha256": hash_file(LAUNCHER),
                "launcher_bytes": LAUNCHER.stat().st_size,
                "msfrpcd_sha256": hash_file(MSFRPCD),
                "msgrpc_sha256": hash_file(MSGRPC),
                "msfrpcd_env_credentials_source_lines": [208, 209],
                "msgrpc_prints_credentials_source_lines": [49, 50],
            },
            "protected_processes_before": [asdict(value) for value in self.protected_before],
            "protected_processes_after": [asdict(value) for value in self.protected_after],
            "candidates": self.candidates,
            "decision": {
                "selected": "systemd-load-credential",
                "reason": (
                    "user manager reads the one-shot AF_UNIX source into a read-only, "
                    "unit-lifetime credential and removes it with the unit"
                ),
                "fallback": "direct-socket",
                "shared_residual_exposure": (
                    "the final MSF_RPC_USER/MSF_RPC_PASS environment remains readable by "
                    "same-UID subjects through /proc while msfrpcd is running"
                ),
            },
            "frozen_contract": {
                "rpc_transport": "TLS + standard MessagePack over /api/",
                "bind_host": "127.0.0.1",
                "msfrpcd_flags": ["-f", "-a", "127.0.0.1", "-p", "<dynamic>", "-t", "2", "-n"],
                "omitted_flags": ["-j", "-S", "-U", "-P"],
                "credential_channel": "systemd LoadCredential from one-shot AF_UNIX socket",
                "launcher_sha256": hash_file(LAUNCHER),
                "token_timeout_seconds": TOKEN_TIMEOUT_SECONDS,
                "readonly_reauth_max": 1,
                "execute_auto_replay": False,
                "msgrpc_managed_path": "disabled",
            },
            "assertions": self.assertions,
            "references": [
                "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials",
                "https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html",
                "local msfrpcd and lib/msf/core/rpc/v10 source from the locked RPM",
            ],
        }

    def _run_candidate(self, runtime_root: Path, channel: str) -> dict[str, Any]:
        candidate_root = runtime_root / channel
        home = candidate_root / "home"
        config_root = home / ".msf4"
        channel_root = candidate_root / "channel"
        log_path = candidate_root / "msfrpcd.log"
        socket_root = (
            Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "fd-msf-r0"
        )
        socket_path = socket_root / f"c-{secrets.token_hex(6)}.sock"
        for directory in (candidate_root, home, config_root, channel_root):
            make_private_directory(directory)
        create_private_file(log_path)

        username = f"fd_{secrets.token_hex(12)}"
        password = secrets.token_urlsafe(48)
        secret_values = [username.encode(), password.encode()]
        payload = encode_credential(username, password)
        unit = f"flagdeck-msf-r0-{channel.replace('-', '')}-{secrets.token_hex(6)}.service"
        port = reserve_loopback_port()
        invocation_id: str | None = None
        main_pid: int | None = None
        started = time.perf_counter()

        with OneShotCredentialServer(socket_path, payload) as credential_server:
            command = systemd_run_command(
                channel=channel,
                unit=unit,
                port=port,
                home=home,
                config_root=config_root,
                log_path=log_path,
                socket_path=socket_path,
            )
            assert_no_secret(command_argv_bytes(command), secret_values, "systemd-run argv")
            try:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=control_environment(),
                    check=False,
                    timeout=40,
                )
                assert_no_secret(completed.stdout, secret_values, "systemd-run output")
                if completed.returncode != 0:
                    raise GateFailure(
                        f"systemd-run failed for {channel}: "
                        f"{completed.stdout.decode(errors='replace')[:1000]}"
                    )
                credential_server.wait_sent()
                if credential_server.peer_uid != os.getuid():
                    raise GateFailure("credential channel peer UID differs from the current UID")

                properties = wait_for_service(unit, log_path)
                invocation_id = required_property(properties, "InvocationID")
                main_pid = int(required_property(properties, "MainPID"))
                if main_pid <= 0:
                    raise GateFailure("systemd reported an invalid MainPID")
                listener = wait_for_owned_listener(main_pid, port, log_path)
                verify_unit_ownership(unit, properties, main_pid, listener)
                startup_seconds = time.perf_counter() - started

                client = MsfRpcClient(
                    host="127.0.0.1",
                    port=port,
                    username=username,
                    password=password,
                    timeout_seconds=20,
                )
                fingerprint = pin_with_retry(client, log_path)
                login = client.login()
                first_token = client.token
                if first_token is None:
                    raise GateFailure("RPC login did not return a token")
                secret_values.append(first_token.encode())

                core_version = require_mapping(client.call_readonly("core.version"))
                module_info = require_mapping(
                    client.call_readonly("module.info", RPC_MODULE_TYPE, RPC_MODULE_NAME)
                )
                time.sleep(TOKEN_IDLE_WAIT_SECONDS)
                expired_error = expect_expired_token(client)
                replayed_version = require_mapping(client.call_readonly("core.version"))
                second_token = client.token
                if second_token is None or second_token == first_token:
                    raise GateFailure("read-only reauthentication did not rotate the token")
                secret_values.append(second_token.encode())
                if client.reauth_count != 1 or client.readonly_replay_count != 1:
                    raise GateFailure("read-only reauthentication count differs from one")
                assert_execute_replay_disabled(client)

                live_scan = scan_live_surfaces(
                    unit=unit,
                    pid=main_pid,
                    runtime_root=candidate_root,
                    secret_values=secret_values,
                    channel=channel,
                )
                logout = client.logout()
                if logout.get("result") != "success":
                    raise GateFailure("auth.logout failed")

                selected_properties = select_unit_properties(properties)
                credential_peer = {
                    "pid": credential_server.peer_pid,
                    "uid": credential_server.peer_uid,
                    "gid": credential_server.peer_gid,
                }
                rpc_evidence = {
                    "certificate_sha256": fingerprint,
                    "login_result": login.get("result"),
                    "core_version": safe_core_version(core_version),
                    "module_info": safe_module_info(module_info),
                    "token_expired_after_idle": True,
                    "expired_error_status": expired_error.status,
                    "readonly_reauth_count": client.reauth_count,
                    "readonly_replay_count": client.readonly_replay_count,
                    "replayed_core_version_equal": replayed_version == core_version,
                    "logout_result": logout.get("result"),
                    "execute_auto_replay": False,
                }
            finally:
                cleanup = stop_owned_unit(
                    unit=unit,
                    expected_invocation_id=invocation_id,
                    expected_pid=main_pid,
                    launcher=LAUNCHER,
                    port=port,
                )

        cleanup["source_socket_gone"] = not socket_path.exists()
        if not all(cleanup.values()):
            raise GateFailure(f"owned unit cleanup incomplete: {cleanup}")
        post_scan = scan_post_stop_surfaces(
            unit=unit,
            runtime_root=candidate_root,
            secret_values=secret_values,
            pid=main_pid,
        )
        if any(post_scan.values()):
            raise GateFailure(f"secret remained after unit stop: {post_scan}")
        if socket_path.exists():
            raise GateFailure("credential socket remained after lifecycle")

        return {
            "channel": channel,
            "unit": unit,
            "startup_seconds": startup_seconds,
            "password_random_input_bytes": 48,
            "password_ascii_bytes": len(password.encode()),
            "password_entropy_source": "secrets.token_urlsafe(48), at least 384 random bits",
            "credential_peer": credential_peer,
            "unit_properties": selected_properties,
            "listener": asdict(listener),
            "rpc": rpc_evidence,
            "leak_scan_live": live_scan,
            "leak_scan_after_stop": post_scan,
            "cleanup": cleanup,
            "command_contract": {
                "shell": False,
                "absolute_launcher": str(LAUNCHER),
                "absolute_target": str(MSFRPCD),
                "secrets_in_argv": False,
                "systemd_environment_secret_transport": False,
                "transient_unit_secret_literal": False,
            },
        }

    def _evaluate_assertions(self, runtime_root: Path) -> None:
        before = {(item.pid, item.start_time_ticks) for item in self.protected_before}
        after = {(item.pid, item.start_time_ticks) for item in self.protected_after}
        self.assertions["preexisting_processes_unchanged"] = before == after
        self.assertions["both_channels_passed"] = len(self.candidates) == 2
        self.assertions["loopback_listener_owned"] = all(
            candidate["listener"]["host"] == "127.0.0.1" for candidate in self.candidates
        )
        self.assertions["tls_pinned"] = all(
            len(candidate["rpc"]["certificate_sha256"]) == 64 for candidate in self.candidates
        )
        self.assertions["readonly_rpc_and_expiry_passed"] = all(
            candidate["rpc"]["token_expired_after_idle"]
            and candidate["rpc"]["readonly_reauth_count"] == 1
            and candidate["rpc"]["logout_result"] == "success"
            for candidate in self.candidates
        )
        self.assertions["only_expected_live_secret_exposure"] = all(
            candidate["leak_scan_live"]["unexpected_surface_count"] == 0
            and candidate["leak_scan_live"]["proc_environ"]
            for candidate in self.candidates
        )
        self.assertions["full_cleanup"] = all(
            all(candidate["cleanup"].values()) for candidate in self.candidates
        )
        self.assertions["no_runtime_secret_after_stop"] = all(
            not any(candidate["leak_scan_after_stop"].values()) for candidate in self.candidates
        )
        self.assertions["source_tree_has_no_runtime_secret"] = all(
            not candidate["leak_scan_live"]["source_files"] for candidate in self.candidates
        )
        self.assertions["runtime_root_private"] = stat.S_IMODE(runtime_root.stat().st_mode) == 0o700


def systemd_run_command(
    *,
    channel: str,
    unit: str,
    port: int,
    home: Path,
    config_root: Path,
    log_path: Path,
    socket_path: Path,
) -> list[str]:
    systemd_run = require_command("systemd-run")
    command = [
        systemd_run,
        "--user",
        "--unit",
        unit,
        "--collect",
        "--service-type=exec",
        "--expand-environment=no",
        "--description=FlagDeck R0 Metasploit RPC",
        "--property=KillMode=control-group",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=yes",
        "--property=MemoryMax=1073741824",
        "--property=TasksMax=256",
        "--property=CPUQuota=200%",
        "--property=UMask=0077",
        "--property=TimeoutStopSec=10s",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=WorkingDirectory=/opt/metasploit-framework/embedded/framework",
        f"--property=StandardOutput=append:{log_path}",
        f"--property=StandardError=append:{log_path}",
    ]
    if channel == "systemd-load-credential":
        command.append(f"--property=LoadCredential=flagdeck.msf-rpc:{socket_path}")
        launcher_channel = "systemd-credential"
        source = "flagdeck.msf-rpc"
    elif channel == "direct-socket":
        launcher_channel = "direct-socket"
        source = str(socket_path)
    else:
        raise ValueError(f"unsupported channel: {channel}")
    command.extend(
        [
            str(LAUNCHER),
            "--channel",
            launcher_channel,
            "--source",
            source,
            "--target",
            str(MSFRPCD),
            "--home",
            str(home),
            "--config-root",
            str(config_root),
            "--port",
            str(port),
            "--token-timeout",
            str(TOKEN_TIMEOUT_SECONDS),
        ]
    )
    return command


def wait_for_service(unit: str, log_path: Path, timeout_seconds: float = 90.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        last = systemctl_show(unit)
        if last.get("ActiveState") == "active" and int(last.get("MainPID", "0")) > 0:
            return last
        if last.get("ActiveState") == "failed":
            raise GateFailure(f"unit failed during startup: {bounded_log(log_path)}")
        time.sleep(0.1)
    raise GateFailure(f"unit did not become active: {last}, {bounded_log(log_path)}")


def wait_for_owned_listener(
    pid: int, port: int, log_path: Path, timeout_seconds: float = 90.0
) -> ListenerRecord:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        listeners = listeners_owned_by_pid(pid, port)
        if len(listeners) == 1:
            return listeners[0]
        if not Path(f"/proc/{pid}").exists():
            raise GateFailure(f"msfrpcd exited before listening: {bounded_log(log_path)}")
        time.sleep(0.1)
    raise GateFailure(f"msfrpcd listener timeout: {bounded_log(log_path)}")


def pin_with_retry(client: MsfRpcClient, log_path: Path) -> str:
    deadline = time.monotonic() + 30
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return client.pin_current_endpoint()
        except (OSError, TimeoutError) as error:
            last_error = error
            time.sleep(0.1)
    raise GateFailure(f"TLS pin failed: {last_error}, {bounded_log(log_path)}")


def expect_expired_token(client: MsfRpcClient) -> RpcError:
    try:
        client.call_authenticated("core.version")
    except RpcError as error:
        if error.invalid_authentication:
            return error
        raise
    raise GateFailure("temporary RPC token remained valid after idle timeout")


def assert_execute_replay_disabled(client: MsfRpcClient) -> None:
    if "module.execute" in IDEMPOTENT_READ_METHODS:
        raise GateFailure("module.execute appears in the replay allow-list")
    try:
        client.call_readonly("module.execute", "exploit", "multi/handler", {})
    except ReplayPolicyError:
        return
    raise GateFailure("execution RPC automatic replay policy was not enforced")


def verify_unit_ownership(
    unit: str,
    properties: dict[str, str],
    pid: int,
    listener: ListenerRecord,
) -> None:
    if listener.host != "127.0.0.1":
        raise GateFailure(f"RPC listener is not IPv4 loopback: {listener}")
    control_group = required_property(properties, "ControlGroup")
    process_cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip()
    if f"0::{control_group}" not in process_cgroup:
        raise GateFailure("MainPID cgroup differs from the transient unit")
    cgroup_procs = Path("/sys/fs/cgroup") / control_group.lstrip("/") / "cgroup.procs"
    if pid not in {int(value) for value in cgroup_procs.read_text().split()}:
        raise GateFailure("MainPID is absent from the transient unit cgroup")
    exec_start = properties.get("ExecStart", "")
    if str(LAUNCHER) not in exec_start:
        raise GateFailure("transient unit ExecStart does not contain the trusted launcher")
    fragment = properties.get("FragmentPath", "")
    expected_fragment_root = (
        Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
        / "systemd"
        / "transient"
    )
    if fragment and Path(fragment).parent != expected_fragment_root:
        raise GateFailure("transient unit fragment is outside the user manager runtime")
    if properties.get("KillMode") != "control-group" or properties.get("LimitCORE") != "0":
        raise GateFailure("transient unit safety properties differ")
    if properties.get("NoNewPrivileges") != "yes":
        raise GateFailure("NoNewPrivileges is disabled")
    if not unit.startswith("flagdeck-msf-r0-"):
        raise GateFailure("unit name is outside the owned prefix")


def scan_live_surfaces(
    *,
    unit: str,
    pid: int,
    runtime_root: Path,
    secret_values: list[bytes],
    channel: str,
) -> dict[str, Any]:
    systemctl_data = command_bytes(["systemctl", "--user", "show", unit, "--all", "--no-pager"])
    journal_data = command_bytes(
        ["journalctl", "--user-unit", unit, "--no-pager", "--output=cat"], check=False
    )
    dbus_data, dbus_available = dbus_unit_surface(unit)
    properties = systemctl_show(unit)
    fragment = Path(properties.get("FragmentPath", ""))
    fragment_data = fragment.read_bytes() if fragment.is_file() else b""
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    environ = Path(f"/proc/{pid}/environ").read_bytes()
    log_data = next(runtime_root.glob("msfrpcd.log")).read_bytes()
    runtime_files = scan_tree_for_secrets(runtime_root, secret_values)
    source_files = scan_tree_for_secrets(SPIKE_ROOT, secret_values, skip={".venv", "evidence"})
    credential_path = credential_runtime_path(unit)
    credential_hit = credential_path.is_file() and file_contains_secret(
        credential_path, secret_values
    )

    surface_hits = {
        "systemctl_show": contains_secret(systemctl_data, secret_values),
        "dbus_visible_properties": contains_secret(dbus_data, secret_values),
        "journal": contains_secret(journal_data, secret_values),
        "proc_cmdline": contains_secret(cmdline, secret_values),
        "ordinary_log": contains_secret(log_data, secret_values),
        "transient_unit_fragment": contains_secret(fragment_data, secret_values),
        "runtime_files": runtime_files,
        "source_files": source_files,
    }
    unexpected_count = sum(bool(value) for value in surface_hits.values())
    proc_environment_hit = contains_secret(environ, secret_values[:2])
    if not proc_environment_hit:
        raise GateFailure("same-UID /proc environ exposure was not measurable")
    expected_credential_file = channel == "systemd-load-credential"
    if credential_hit != expected_credential_file:
        raise GateFailure(
            f"systemd credential file exposure mismatch: {credential_path}, {credential_hit}"
        )
    return {
        **surface_hits,
        "unexpected_surface_count": unexpected_count,
        "proc_environ": proc_environment_hit,
        "proc_environ_exposed_keys": ["MSF_RPC_USER", "MSF_RPC_PASS"],
        "systemd_credential_file": credential_hit,
        "systemd_credential_file_expected": expected_credential_file,
        "dbus_scan_available": dbus_available,
    }


def scan_post_stop_surfaces(
    *,
    unit: str,
    runtime_root: Path,
    secret_values: list[bytes],
    pid: int | None,
) -> dict[str, bool]:
    journal = command_bytes(
        ["journalctl", "--user-unit", unit, "--no-pager", "--output=cat"], check=False
    )
    core_dump = b""
    if pid is not None:
        core_dump = command_bytes(
            ["coredumpctl", "--no-pager", "--json=short", "list", str(pid)], check=False
        )
    return {
        "journal": contains_secret(journal, secret_values),
        "ordinary_and_runtime_files": scan_tree_for_secrets(runtime_root, secret_values),
        "coredump_metadata": contains_secret(core_dump, secret_values),
        "systemd_credential_file": credential_runtime_path(unit).exists(),
        "proc_environ": pid is not None and Path(f"/proc/{pid}/environ").exists(),
    }


def stop_owned_unit(
    *,
    unit: str,
    expected_invocation_id: str | None,
    expected_pid: int | None,
    launcher: Path,
    port: int,
) -> dict[str, bool]:
    properties = systemctl_show(unit)
    active = properties.get("LoadState") == "loaded" and properties.get("ActiveState") not in {
        "inactive",
        "failed",
    }
    if active:
        invocation = properties.get("InvocationID")
        exec_start = properties.get("ExecStart", "")
        if expected_invocation_id is not None and invocation != expected_invocation_id:
            raise GateFailure("refusing to stop unit with a changed InvocationID")
        if str(launcher) not in exec_start or not unit.startswith("flagdeck-msf-r0-"):
            raise GateFailure("refusing to stop a unit without launcher ownership evidence")
        completed = subprocess.run(
            [require_command("systemctl"), "--user", "stop", unit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=control_environment(),
            check=False,
            timeout=20,
        )
        if completed.returncode != 0:
            raise GateFailure(
                f"owned unit stop failed: {completed.stdout.decode(errors='replace')}"
            )

    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        pid_gone = expected_pid is None or not Path(f"/proc/{expected_pid}").exists()
        if pid_gone and not listener_exists(port):
            break
        time.sleep(0.1)
    final = systemctl_show(unit)
    process_gone = expected_pid is None or not Path(f"/proc/{expected_pid}").exists()
    listener_gone = not listener_exists(port)
    cgroup_path = (
        Path("/sys/fs/cgroup") / final.get("ControlGroup", "").lstrip("/")
        if final.get("ControlGroup")
        else None
    )
    cgroup_gone = cgroup_path is None or not cgroup_path.exists()
    if cgroup_path is not None and cgroup_path.exists():
        procs = cgroup_path / "cgroup.procs"
        cgroup_gone = not procs.exists() or not procs.read_text().strip()
    credential_gone = not credential_runtime_path(unit).exists()
    unit_inactive = final.get("LoadState") == "not-found" or final.get("ActiveState") in {
        "inactive",
        "failed",
        None,
    }
    cleanup = {
        "process_gone": process_gone,
        "listener_gone": listener_gone,
        "cgroup_gone_or_empty": cgroup_gone,
        "credential_copy_gone": credential_gone,
        "unit_inactive_or_collected": unit_inactive,
    }
    return cleanup


def systemctl_show(unit: str) -> dict[str, str]:
    completed = subprocess.run(
        [require_command("systemctl"), "--user", "show", unit, "--all", "--no-pager"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=control_environment(),
        check=False,
        timeout=10,
    )
    properties: dict[str, str] = {}
    for line in completed.stdout.decode(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    return properties


def dbus_unit_surface(unit: str) -> tuple[bytes, bool]:
    get_unit = subprocess.run(
        [
            require_command("busctl"),
            "--user",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            "s",
            unit,
        ],
        capture_output=True,
        env=control_environment(),
        check=False,
        timeout=10,
    )
    if get_unit.returncode != 0:
        return get_unit.stdout + get_unit.stderr, False
    match = re.search(rb'"([^"]+)"', get_unit.stdout)
    if match is None:
        return get_unit.stdout, False
    path = match.group(1).decode("ascii", errors="strict")
    introspect = subprocess.run(
        [
            require_command("busctl"),
            "--user",
            "introspect",
            "org.freedesktop.systemd1",
            path,
            "--no-pager",
        ],
        capture_output=True,
        env=control_environment(),
        check=False,
        timeout=10,
    )
    return get_unit.stdout + introspect.stdout + introspect.stderr, introspect.returncode == 0


def listeners_owned_by_pid(pid: int, port: int) -> list[ListenerRecord]:
    inodes: set[str] = set()
    with suppress(FileNotFoundError):
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            with suppress(OSError):
                target = os.readlink(fd)
                if target.startswith("socket:[") and target.endswith("]"):
                    inodes.add(target[8:-1])
    listeners: list[ListenerRecord] = []
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for line in table.read_text().splitlines()[1:]:
            columns = line.split()
            if len(columns) < 10 or columns[3] != "0A" or columns[9] not in inodes:
                continue
            address_text, port_hex = columns[1].split(":")
            if int(port_hex, 16) != port:
                continue
            if table.name == "tcp":
                host = socket.inet_ntoa(bytes.fromhex(address_text)[::-1])
            else:
                raw = bytes.fromhex(address_text)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            listeners.append(ListenerRecord(host, port, columns[9]))
    return listeners


def listener_exists(port: int) -> bool:
    port_hex = f"{port:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for line in table.read_text().splitlines()[1:]:
            columns = line.split()
            if len(columns) >= 4 and columns[3] == "0A" and columns[1].endswith(f":{port_hex}"):
                return True
    return False


def snapshot_protected_processes() -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmdline = proc.joinpath("cmdline").read_bytes().split(b"\0")
            arguments = [value.decode(errors="replace") for value in cmdline if value]
            if not arguments or not is_protected_process(arguments):
                continue
            records.append(
                ProcessRecord(
                    pid=int(proc.name),
                    start_time_ticks=process_start_ticks(proc),
                    executable=os.readlink(proc / "exe"),
                    argv=redact_msf_argv(arguments),
                    cgroup=proc.joinpath("cgroup").read_text().strip(),
                )
            )
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return sorted(records, key=lambda value: value.pid)


def is_protected_process(arguments: list[str]) -> bool:
    basename = Path(arguments[0]).name
    joined = " ".join(arguments)
    return basename in {"msfrpcd", "msfconsole", "postgres"} and (
        basename != "postgres" or ".msf4/db" in joined
    )


def process_start_ticks(proc: Path) -> int:
    data = proc.joinpath("stat").read_text()
    closing = data.rfind(")")
    fields = data[closing + 2 :].split()
    return int(fields[19])


def redact_msf_argv(arguments: list[str]) -> list[str]:
    output = list(arguments)
    for index, value in enumerate(output[:-1]):
        if value in {"-P", "-U", "--password", "--username"}:
            output[index + 1] = "<redacted>"
    return output


def credential_runtime_path(unit: str) -> Path:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    return runtime / "credentials" / unit / "flagdeck.msf-rpc"


def select_unit_properties(properties: dict[str, str]) -> dict[str, str]:
    names = (
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
        "ActiveState",
        "SubState",
        "KillMode",
        "LimitCORE",
        "NoNewPrivileges",
        "MemoryMax",
        "TasksMax",
        "CPUQuotaPerSecUSec",
        "RestrictAddressFamilies",
        "Environment",
        "LoadCredential",
        "FragmentPath",
        "StandardOutput",
        "StandardError",
    )
    return {name: properties.get(name, "") for name in names}


def required_property(properties: dict[str, str], name: str) -> str:
    value = properties.get(name)
    if not value:
        raise GateFailure(f"systemd property {name} is missing")
    return value


def safe_core_version(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value.get(key) for key in ("version", "ruby", "api")}


def safe_module_info(value: dict[str, Any]) -> dict[str, Any]:
    description = value.get("description")
    return {
        "name": value.get("name"),
        "fullname": value.get("fullname"),
        "rank": value.get("rank"),
        "type": value.get("type"),
        "description_bytes": len(description.encode()) if isinstance(description, str) else None,
    }


def contains_secret(data: bytes, secrets_to_find: list[bytes]) -> bool:
    return any(value and value in data for value in secrets_to_find)


def assert_no_secret(data: bytes, secrets_to_find: list[bytes], surface: str) -> None:
    if contains_secret(data, secrets_to_find):
        raise GateFailure(f"secret found in {surface}")


def scan_tree_for_secrets(
    root: Path, secrets_to_find: list[bytes], *, skip: set[str] | None = None
) -> bool:
    skipped = skip or set()
    if not root.exists():
        return False
    for path in root.rglob("*"):
        if any(part in skipped for part in path.parts) or not path.is_file():
            continue
        with suppress(OSError):
            if path.stat().st_size <= SECRET_SCAN_FILE_LIMIT and file_contains_secret(
                path, secrets_to_find
            ):
                return True
    return False


def file_contains_secret(path: Path, secrets_to_find: list[bytes]) -> bool:
    if not secrets_to_find:
        return False
    overlap = max((len(value) for value in secrets_to_find), default=1) - 1
    tail = b""
    with path.open("rb", buffering=0) as source:
        while chunk := source.read(64 * 1024):
            data = tail + chunk
            if contains_secret(data, secrets_to_find):
                return True
            tail = data[-overlap:] if overlap else b""
    return False


def make_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def create_private_file(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    os.close(fd)


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def control_environment() -> dict[str, str]:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def require_command(name: str) -> str:
    path = shutil.which(name, path="/usr/bin:/bin")
    if path is None:
        raise GateFailure(f"required command is unavailable: {name}")
    return str(Path(path).resolve())


def require_executable(path: Path) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise GateFailure(f"required executable is unavailable: {path}")


def command_bytes(arguments: list[str], *, check: bool = True) -> bytes:
    resolved = list(arguments)
    if not Path(resolved[0]).is_absolute():
        resolved[0] = require_command(resolved[0])
    completed = subprocess.run(
        resolved,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=control_environment(),
        check=False,
        timeout=20,
    )
    if check and completed.returncode != 0:
        raise GateFailure(f"command failed: {arguments[0]}")
    return completed.stdout


def command_text(arguments: list[str]) -> str:
    return command_bytes(arguments).decode(errors="replace").strip()


def command_argv_bytes(arguments: list[str]) -> bytes:
    return b"\0".join(os.fsencode(value) for value in arguments)


def bounded_log(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="replace")[-4000:]


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    make_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
    fd = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir", type=Path, default=SPIKE_ROOT / "evidence", help="output directory"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    evidence_dir = arguments.evidence_dir.resolve()
    runner = GateRunner()
    started = time.perf_counter()
    runtime_root = evidence_dir / "runtime"
    if runtime_root.exists():
        shutil.rmtree(runtime_root)
    make_private_directory(runtime_root)
    try:
        results = runner.run(runtime_root)
        results["gate_duration_seconds"] = time.perf_counter() - started
        write_private_json(evidence_dir / "results.json", results)
        summary = {
            "schema": results["schema"],
            "status": results["status"],
            "gate_duration_seconds": results["gate_duration_seconds"],
            "assertions": results["assertions"],
            "selected_channel": results["decision"]["selected"],
            "candidate_startup_seconds": {
                value["channel"]: value["startup_seconds"] for value in results["candidates"]
            },
        }
        write_private_json(evidence_dir / "summary.json", summary)
        (evidence_dir / "failure.json").unlink(missing_ok=True)
        shutil.rmtree(runtime_root)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except BaseException as error:
        failure = {
            "schema": "flagdeck.metasploit-rpc-r0.v1",
            "status": "FAIL",
            "gate_duration_seconds": time.perf_counter() - started,
            "error": f"{type(error).__name__}:{str(error)[:2000]}",
            "candidate_count": len(runner.candidates),
        }
        write_private_json(evidence_dir / "failure.json", failure)
        print(json.dumps(failure, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
