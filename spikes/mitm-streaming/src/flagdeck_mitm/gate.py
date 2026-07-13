"""Executable real-proxy gate for FlagDeck's mitmproxy streaming contract."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.metadata
import json
import os
import platform
import signal
import socket
import ssl
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from .capture import CaptureMode, FaultKind
from .fixture import (
    IO_CHUNK,
    FixtureCertificatePaths,
    FixtureFile,
    FixtureServers,
    FixtureState,
    generate_fixture_certificates,
    generate_fixture_files,
    hash_file,
)

MIB = 1024 * 1024
RSS_LIMIT_KIB = 32 * 1024
SPIKE_ROOT = Path(__file__).resolve().parents[2]
MITMDUMP = SPIKE_ROOT / ".venv" / "bin" / "mitmdump"
ADDON_SCRIPT = SPIKE_ROOT / "flagdeck_worker_addon.py"
SOURCE_ROOT = SPIKE_ROOT / "src"


class GateFailure(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProxySettings:
    name: str
    mode: CaptureMode = CaptureMode.PASS_THROUGH
    queue_bytes: int = 4 * MIB
    queue_frames: int = 256
    enqueue_timeout_seconds: float = 0.25
    ack_timeout_seconds: float = 5.0
    max_active_captures: int = 8
    fault_kind: FaultKind = FaultKind.NONE
    fault_after_bytes: int | None = None
    write_delay_seconds: float = 0.0


@dataclass(slots=True)
class ClientResult:
    status: int | None
    body_bytes: int
    sha256: str
    elapsed_seconds: float
    sent_bytes: int = 0
    response_json: dict[str, Any] | None = None
    content_encoding: str | None = None
    error: str | None = None
    token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RssSampler:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._current_case: str | None = None
        self._case_peaks: dict[str, int] = {}
        self._global_peak = 0
        self._thread = threading.Thread(target=self._run, name=f"rss-{pid}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def begin_case(self, name: str) -> int:
        sample = process_tree_rss_kib(self.pid)
        with self._lock:
            self._current_case = name
            self._case_peaks[name] = sample
        return sample

    def end_case(self, name: str) -> int:
        sample = process_tree_rss_kib(self.pid)
        with self._lock:
            self._case_peaks[name] = max(self._case_peaks.get(name, 0), sample)
            self._current_case = None
            return self._case_peaks[name]

    @property
    def global_peak_kib(self) -> int:
        with self._lock:
            return self._global_peak

    def baseline(self) -> int:
        samples: list[int] = []
        for _ in range(10):
            samples.append(process_tree_rss_kib(self.pid))
            time.sleep(0.02)
        return int(statistics.median(samples))

    def _run(self) -> None:
        while not self._stop.wait(0.01):
            sample = process_tree_rss_kib(self.pid)
            with self._lock:
                self._global_peak = max(self._global_peak, sample)
                if self._current_case is not None:
                    name = self._current_case
                    self._case_peaks[name] = max(self._case_peaks.get(name, 0), sample)


class ProxyProcess:
    def __init__(
        self,
        *,
        root: Path,
        settings: ProxySettings,
        fixture_ca: Path,
    ) -> None:
        self.root = root
        self.settings = settings
        self.fixture_ca = fixture_ca
        self.port = reserve_loopback_port()
        self.confdir = root / "confdir"
        self.capture_root = root / "capture"
        self.events_file = root / "events" / "events.jsonl"
        self.home = root / "home"
        self.log_path = root / "mitmdump.log"
        self.process: subprocess.Popen[bytes] | None = None
        self.sampler: RssSampler | None = None
        self.ready_event: dict[str, Any] | None = None
        self.listeners: list[dict[str, Any]] = []
        for directory in (
            self.root,
            self.confdir,
            self.capture_root,
            self.events_file.parent,
            self.home,
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    @property
    def pid(self) -> int:
        if self.process is None:
            raise RuntimeError("proxy has not started")
        return self.process.pid

    def __enter__(self) -> Self:
        if not MITMDUMP.is_file() or not ADDON_SCRIPT.is_file():
            raise GateFailure("locked mitmdump or addon entry point is missing")
        fault_after = (
            -1 if self.settings.fault_after_bytes is None else self.settings.fault_after_bytes
        )
        argv = [
            str(MITMDUMP.resolve()),
            "--quiet",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(self.port),
            "--set",
            f"confdir={self.confdir}",
            "--set",
            "store_streamed_bodies=false",
            "--set",
            f"ssl_verify_upstream_trusted_ca={self.fixture_ca}",
            "-s",
            str(ADDON_SCRIPT.resolve()),
            "--set",
            f"flagdeck_capture_root={self.capture_root}",
            "--set",
            f"flagdeck_events_file={self.events_file}",
            "--set",
            f"flagdeck_capture_mode={self.settings.mode.value}",
            "--set",
            f"flagdeck_queue_bytes={self.settings.queue_bytes}",
            "--set",
            f"flagdeck_queue_frames={self.settings.queue_frames}",
            "--set",
            f"flagdeck_enqueue_timeout={self.settings.enqueue_timeout_seconds}",
            "--set",
            f"flagdeck_ack_timeout={self.settings.ack_timeout_seconds}",
            "--set",
            f"flagdeck_max_active_captures={self.settings.max_active_captures}",
            "--set",
            f"flagdeck_fault_kind={self.settings.fault_kind.value}",
            "--set",
            f"flagdeck_fault_after_bytes={fault_after}",
            "--set",
            f"flagdeck_write_delay={self.settings.write_delay_seconds}",
        ]
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        log_fd = os.open(self.log_path, flags, 0o600)
        env = {
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(SOURCE_ROOT),
        }
        try:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                env=env,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            os.close(log_fd)
        self._wait_ready()
        self.listeners = listeners_owned_by_pid(self.pid, self.port)
        if not self.listeners or any(item["host"] != "127.0.0.1" for item in self.listeners):
            raise GateFailure(f"proxy listener ownership/host check failed: {self.listeners}")
        self.sampler = RssSampler(self.pid)
        self.sampler.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self.sampler is not None:
            self.sampler.stop()
        if self.process is None:
            return
        if self.process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)

    def assert_alive(self) -> None:
        if self.process is None or self.process.poll() is not None:
            tail = self.log_path.read_text(errors="replace")[-4000:]
            raise GateFailure(f"mitmdump exited unexpectedly:\n{tail}")

    def client_ssl_context(self) -> ssl.SSLContext:
        ca_path = self.confdir / "mitmproxy-ca-cert.pem"
        if not ca_path.is_file():
            raise GateFailure("mitmproxy client CA was not created")
        context = ssl.create_default_context(cafile=ca_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def event_sequence(self) -> int:
        events = self.read_events()
        return max((int(event["sequence"]) for event in events), default=0)

    def read_events(self) -> list[dict[str, Any]]:
        if not self.events_file.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.events_file.read_text().splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
        return events

    def wait_for_finals(
        self, *, after_sequence: int, count: int, timeout: float = 15.0
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.assert_alive()
            finals = [
                event
                for event in self.read_events()
                if int(event.get("sequence", 0)) > after_sequence
                and event.get("event") == "body_capture_final"
            ]
            if len(finals) >= count:
                return finals
            time.sleep(0.05)
        recent = [
            event for event in self.read_events() if int(event.get("sequence", 0)) > after_sequence
        ]
        raise GateFailure(f"timed out waiting for {count} final events: {recent}")

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            self.assert_alive()
            for event in self.read_events():
                if event.get("event") == "worker_ready":
                    self.ready_event = event
                    if event.get("store_streamed_bodies") is not False:
                        raise GateFailure("store_streamed_bodies must be false")
                    return
            time.sleep(0.05)
        tail = self.log_path.read_text(errors="replace")[-4000:]
        raise GateFailure(f"proxy readiness timeout:\n{tail}")


class GateRunner:
    def __init__(self, *, large_size: int, small_size: int) -> None:
        self.large_size = large_size
        self.small_size = small_size
        self.cases: list[dict[str, Any]] = []
        self.proxies: list[dict[str, Any]] = []
        self.assertions: dict[str, bool] = {}

    def run(self, runtime_root: Path) -> dict[str, Any]:
        fixture_root = runtime_root / "fixtures"
        files = generate_fixture_files(
            fixture_root / "files", large_size=self.large_size, small_size=self.small_size
        )
        certs = generate_fixture_certificates(fixture_root / "certs")
        with FixtureServers(files, certs) as servers:
            self._run_normal_proxy(runtime_root, servers, certs, files)
            self._run_strict_proxy(runtime_root, servers, certs, files)
            self._run_fault_matrix(runtime_root, servers, certs, files)

        self._evaluate_global_assertions()
        failed = sorted(name for name, passed in self.assertions.items() if not passed)
        if failed:
            raise GateFailure(f"gate assertions failed: {failed}")
        return {
            "schema": "flagdeck.mitm-streaming-r0.v1",
            "status": "PASS",
            "generated_unix_ns": time.time_ns(),
            "versions": {
                "python": platform.python_version(),
                "mitmproxy": importlib.metadata.version("mitmproxy"),
                "uv_lock_sha256": hash_file(SPIKE_ROOT / "uv.lock")[1],
                "mitmdump_sha256": hash_file(MITMDUMP)[1],
                "addon_entry_sha256": hash_file(ADDON_SCRIPT)[1],
            },
            "fixture": {
                "large_bytes": self.large_size,
                "small_bytes": self.small_size,
                "files": {name: fixture.to_dict() for name, fixture in files.items()},
                "hosts": ["127.0.0.1"],
                "tls_upstream_verification": "fixture CA",
            },
            "frozen_contract": {
                "default_mode": CaptureMode.PASS_THROUGH.value,
                "queue_capacity_bytes_per_direction": 4 * MIB,
                "queue_capacity_frames_per_direction": 256,
                "pass_through_enqueue_timeout_seconds": 0.25,
                "ack_timeout_seconds": 5.0,
                "max_active_capture_writers": 8,
                "worker_incremental_rss_limit_kib": RSS_LIMIT_KIB,
                "store_streamed_bodies": False,
                "representation_kind": "semantic",
            },
            "cases": self.cases,
            "proxies": self.proxies,
            "assertions": self.assertions,
            "semantic_scope": {
                "captured": ["semantic HTTP metadata", "raw encoded body bytes"],
                "excluded": [
                    "HTTP/1 chunk boundaries",
                    "header whitespace and original line layout",
                    "HTTP/2 and HTTP/3 frame boundaries",
                    "HPACK or QPACK wire representation",
                    "network packet boundaries",
                ],
            },
        }

    def _run_normal_proxy(
        self,
        runtime_root: Path,
        servers: FixtureServers,
        certs: FixtureCertificatePaths,
        files: dict[str, FixtureFile],
    ) -> None:
        settings = ProxySettings(name="pass-normal")
        proxy_root = runtime_root / "proxies" / settings.name
        with ProxyProcess(root=proxy_root, settings=settings, fixture_ca=certs.ca_cert) as proxy:
            cold_baseline = self._require_sampler(proxy).baseline()
            self._warm_proxy(proxy, servers.http_port)
            steady_baseline = self._require_sampler(proxy).baseline()
            ssl_context = proxy.client_ssl_context()

            for scheme, target_port in (
                ("http", servers.http_port),
                ("https", servers.https_port),
            ):
                self._complete_upload_case(
                    proxy,
                    scheme=scheme,
                    target_port=target_port,
                    source=files["large"],
                    framing="length",
                    ssl_context=ssl_context,
                    name=f"{scheme}-50m-upload-content-length-pass",
                )
                self._complete_download_case(
                    proxy,
                    scheme=scheme,
                    target_port=target_port,
                    source=files["large"],
                    framing="length",
                    ssl_context=ssl_context,
                    name=f"{scheme}-50m-download-content-length-pass",
                )

            self._complete_upload_case(
                proxy,
                scheme="http",
                target_port=servers.http_port,
                source=files["small"],
                framing="chunked",
                ssl_context=None,
                name="http-upload-chunked-pass",
            )
            for fixture_name, framing in (
                ("small", "chunked"),
                ("small", "close"),
                ("gzip", "length"),
                ("brotli", "chunked"),
            ):
                self._complete_download_case(
                    proxy,
                    scheme="http",
                    target_port=servers.http_port,
                    source=files[fixture_name],
                    framing=framing,
                    ssl_context=None,
                    name=f"http-download-{fixture_name}-{framing}-pass",
                )
            self._early_413_case(proxy, servers.http_port)
            self._truncated_response_case(proxy, servers.http_port, files["small"])
            self._record_proxy_metrics(proxy, cold_baseline, steady_baseline)

    def _run_strict_proxy(
        self,
        runtime_root: Path,
        servers: FixtureServers,
        certs: FixtureCertificatePaths,
        files: dict[str, FixtureFile],
    ) -> None:
        settings = ProxySettings(name="strict-normal", mode=CaptureMode.EVIDENCE_STRICT)
        with ProxyProcess(
            root=runtime_root / "proxies" / settings.name,
            settings=settings,
            fixture_ca=certs.ca_cert,
        ) as proxy:
            cold_baseline = self._require_sampler(proxy).baseline()
            self._warm_proxy(proxy, servers.http_port)
            steady_baseline = self._require_sampler(proxy).baseline()
            self._complete_upload_case(
                proxy,
                scheme="http",
                target_port=servers.http_port,
                source=files["large"],
                framing="length",
                ssl_context=None,
                name="http-50m-upload-content-length-strict",
            )
            self._complete_download_case(
                proxy,
                scheme="http",
                target_port=servers.http_port,
                source=files["large"],
                framing="length",
                ssl_context=None,
                name="http-50m-download-content-length-strict",
            )
            self._record_proxy_metrics(proxy, cold_baseline, steady_baseline)

    def _run_fault_matrix(
        self,
        runtime_root: Path,
        servers: FixtureServers,
        certs: FixtureCertificatePaths,
        files: dict[str, FixtureFile],
    ) -> None:
        fault_settings = [
            ProxySettings(name="queue-full-pass", queue_bytes=1024, queue_frames=1),
            ProxySettings(
                name="writer-crash-pass",
                fault_kind=FaultKind.WRITER_CRASH,
                fault_after_bytes=256 * 1024,
            ),
            ProxySettings(
                name="enospc-pass",
                fault_kind=FaultKind.ENOSPC,
                fault_after_bytes=256 * 1024,
            ),
        ]
        for settings in fault_settings:
            with ProxyProcess(
                root=runtime_root / "proxies" / settings.name,
                settings=settings,
                fixture_ca=certs.ca_cert,
            ) as proxy:
                self._fault_pass_case(proxy, servers.http_port, files["small"], settings.name)

        strict_settings = ProxySettings(
            name="writer-crash-strict",
            mode=CaptureMode.EVIDENCE_STRICT,
            fault_kind=FaultKind.WRITER_CRASH,
            fault_after_bytes=256 * 1024,
        )
        with ProxyProcess(
            root=runtime_root / "proxies" / strict_settings.name,
            settings=strict_settings,
            fixture_ca=certs.ca_cert,
        ) as proxy:
            self._fault_strict_case(proxy, servers, files["small"])

    def _complete_upload_case(
        self,
        proxy: ProxyProcess,
        *,
        scheme: str,
        target_port: int,
        source: FixtureFile,
        framing: str,
        ssl_context: ssl.SSLContext | None,
        name: str,
    ) -> None:
        before = proxy.event_sequence()
        sampler = self._require_sampler(proxy)
        rss_before = sampler.begin_case(name)
        client = upload_via_proxy(
            proxy,
            scheme=scheme,
            target_port=target_port,
            source=source,
            framing=framing,
            ssl_context=ssl_context,
        )
        peak = sampler.end_case(name)
        finals = proxy.wait_for_finals(after_sequence=before, count=2)
        request_event = one_direction(finals, "request")
        response_event = one_direction(finals, "response")
        self._assert_client_upload(client, source)
        self._assert_complete_capture(request_event, source)
        self._assert_self_consistent_capture(response_event)
        self._append_case(name, client, finals, rss_before, peak)

    def _complete_download_case(
        self,
        proxy: ProxyProcess,
        *,
        scheme: str,
        target_port: int,
        source: FixtureFile,
        framing: str,
        ssl_context: ssl.SSLContext | None,
        name: str,
    ) -> None:
        before = proxy.event_sequence()
        sampler = self._require_sampler(proxy)
        rss_before = sampler.begin_case(name)
        client = download_via_proxy(
            proxy,
            scheme=scheme,
            target_port=target_port,
            source=source,
            framing=framing,
            ssl_context=ssl_context,
        )
        peak = sampler.end_case(name)
        finals = proxy.wait_for_finals(after_sequence=before, count=1)
        response_event = one_direction(finals, "response")
        if client.error or client.status != 200:
            raise GateFailure(f"download client failed for {name}: {client.to_dict()}")
        if client.body_bytes != source.size or client.sha256 != source.sha256:
            raise GateFailure(f"download integrity mismatch for {name}: {client.to_dict()}")
        if client.content_encoding != source.content_encoding:
            raise GateFailure(f"encoded body metadata mismatch for {name}")
        self._assert_complete_capture(response_event, source)
        self._append_case(name, client, finals, rss_before, peak)

    def _early_413_case(self, proxy: ProxyProcess, target_port: int) -> None:
        name = "early-413-response-before-request-complete"
        before = proxy.event_sequence()
        sampler = self._require_sampler(proxy)
        rss_before = sampler.begin_case(name)
        started = time.perf_counter()
        raw_response, sent = early_413_via_proxy(proxy, target_port)
        elapsed = time.perf_counter() - started
        peak = sampler.end_case(name)
        finals = proxy.wait_for_finals(after_sequence=before, count=2)
        request_event = one_direction(finals, "request")
        response_event = one_direction(finals, "response")
        if b" 413 " not in raw_response.split(b"\r\n", 1)[0]:
            raise GateFailure(f"early 413 was not observed: {raw_response[:160]!r}")
        if request_event["body_state"] != "truncated":
            raise GateFailure(f"early request state was {request_event['body_state']}")
        if response_event["body_state"] != "streamed_complete":
            raise GateFailure(f"early response state was {response_event['body_state']}")
        if request_event["flow_id"] != response_event["flow_id"]:
            raise GateFailure("early request/response flow IDs differ")
        if int(request_event["observed_bytes"]) >= int(request_event["declared_length"]):
            raise GateFailure("early request was unexpectedly complete")
        client = ClientResult(
            status=413,
            body_bytes=len(raw_response),
            sha256=hashlib.sha256(raw_response).hexdigest(),
            elapsed_seconds=elapsed,
            sent_bytes=sent,
        )
        self._append_case(name, client, finals, rss_before, peak)

    def _truncated_response_case(
        self, proxy: ProxyProcess, target_port: int, source: FixtureFile
    ) -> None:
        name = "response-connection-truncated"
        before = proxy.event_sequence()
        sampler = self._require_sampler(proxy)
        rss_before = sampler.begin_case(name)
        client = download_via_proxy(
            proxy,
            scheme="http",
            target_port=target_port,
            source=source,
            framing="truncate",
            ssl_context=None,
        )
        peak = sampler.end_case(name)
        finals = proxy.wait_for_finals(after_sequence=before, count=1)
        event = one_direction(finals, "response")
        if event["body_state"] != "truncated":
            raise GateFailure(f"truncated response state was {event['body_state']}")
        if int(event["captured_bytes"]) >= source.size:
            raise GateFailure("truncated response captured a complete body")
        if event.get("sha256") is None or event.get("artifact_path") is None:
            raise GateFailure("truncated prefix was not durably committed")
        self._verify_artifact(event)
        if client.error is None or client.body_bytes >= source.size:
            raise GateFailure("client did not observe response truncation")
        self._append_case(name, client, finals, rss_before, peak)

    def _fault_pass_case(
        self, proxy: ProxyProcess, target_port: int, source: FixtureFile, name: str
    ) -> None:
        before = proxy.event_sequence()
        client = upload_via_proxy(
            proxy,
            scheme="http",
            target_port=target_port,
            source=source,
            framing="length",
            ssl_context=None,
        )
        finals = proxy.wait_for_finals(after_sequence=before, count=2)
        event = one_direction(finals, "request")
        self._assert_client_upload(client, source)
        if event["body_state"] != "capture_failed":
            raise GateFailure(f"{name} did not mark capture_failed: {event}")
        if int(event["forwarded_bytes"]) != source.size:
            raise GateFailure(f"{name} did not pass the full body")
        if event.get("artifact_path") is not None or event.get("sha256") is not None:
            raise GateFailure(f"{name} promoted failed evidence")
        expected_reason = {
            "queue-full-pass": "queue_full",
            "writer-crash-pass": "RuntimeError:injected writer crash",
            "enospc-pass": "OSError:errno=28",
        }[name]
        if event.get("failure_reason") != expected_reason:
            raise GateFailure(f"{name} reason mismatch: {event.get('failure_reason')}")
        self._append_case(name, client, finals, None, None)

    def _fault_strict_case(
        self, proxy: ProxyProcess, servers: FixtureServers, source: FixtureFile
    ) -> None:
        name = "writer-crash-strict"
        before = proxy.event_sequence()
        client = upload_via_proxy(
            proxy,
            scheme="http",
            target_port=servers.http_port,
            source=source,
            framing="length",
            ssl_context=None,
            allow_error=True,
        )
        finals = proxy.wait_for_finals(after_sequence=before, count=1)
        event = one_direction(finals, "request")
        if event["body_state"] != "capture_failed":
            raise GateFailure(f"strict writer failure state mismatch: {event}")
        forwarded = int(event["forwarded_bytes"])
        observed = int(event["observed_bytes"])
        if not (0 < forwarded < source.size and forwarded < observed <= source.size):
            raise GateFailure(f"strict forwarded prefix is inaccurate: {event}")
        if client.error is None:
            raise GateFailure("strict writer failure did not fail the client request")
        if client.token is None:
            raise GateFailure("strict upload token is missing")
        upstream = wait_for_upload_result(servers.state, client.token)
        upstream_received = int(upstream["received_bytes"])
        if not (0 < upstream_received <= forwarded < source.size):
            raise GateFailure(
                f"strict target prefix exceeds acknowledged forwarding: {upstream}, {event}"
            )
        if upstream.get("complete") is not False:
            raise GateFailure(f"strict target reported a complete body: {upstream}")
        client.response_json = upstream
        self._append_case(name, client, finals, None, None)

    def _warm_proxy(self, proxy: ProxyProcess, target_port: int) -> None:
        before = proxy.event_sequence()
        result = simple_get(proxy, target_port, "/health")
        if result.status != 200 or result.body_bytes != 2:
            raise GateFailure(f"proxy warmup failed: {result.to_dict()}")
        finals = proxy.wait_for_finals(after_sequence=before, count=1)
        self._assert_self_consistent_capture(one_direction(finals, "response"))

    def _record_proxy_metrics(
        self, proxy: ProxyProcess, cold_baseline: int, steady_baseline: int
    ) -> None:
        sampler = self._require_sampler(proxy)
        peak = sampler.global_peak_kib
        self.proxies.append(
            {
                "name": proxy.settings.name,
                "pid": proxy.pid,
                "port": proxy.port,
                "listeners": proxy.listeners,
                "cold_baseline_rss_kib": cold_baseline,
                "steady_baseline_rss_kib": steady_baseline,
                "peak_rss_kib": peak,
                "incremental_rss_kib": max(0, peak - steady_baseline),
                "settings": {
                    "mode": proxy.settings.mode.value,
                    "queue_bytes": proxy.settings.queue_bytes,
                    "queue_frames": proxy.settings.queue_frames,
                    "enqueue_timeout_seconds": proxy.settings.enqueue_timeout_seconds,
                    "ack_timeout_seconds": proxy.settings.ack_timeout_seconds,
                },
            }
        )

    def _append_case(
        self,
        name: str,
        client: ClientResult,
        finals: list[dict[str, Any]],
        rss_before: int | None,
        peak_rss: int | None,
    ) -> None:
        throughput = (
            client.body_bytes / MIB / client.elapsed_seconds if client.elapsed_seconds > 0 else None
        )
        self.cases.append(
            {
                "name": name,
                "client": client.to_dict(),
                "throughput_mib_per_second": throughput,
                "rss_before_kib": rss_before,
                "peak_rss_kib": peak_rss,
                "captures": [sanitize_capture_event(event) for event in finals],
            }
        )

    def _assert_client_upload(self, client: ClientResult, source: FixtureFile) -> None:
        if client.error or client.status != 200 or client.response_json is None:
            raise GateFailure(f"upload client failed: {client.to_dict()}")
        response = client.response_json
        if (
            response.get("complete") is not True
            or int(response.get("received_bytes", -1)) != source.size
            or response.get("sha256") != source.sha256
        ):
            raise GateFailure(f"upstream upload integrity mismatch: {response}")

    def _assert_complete_capture(self, event: dict[str, Any], source: FixtureFile) -> None:
        if event.get("body_state") != "streamed_complete":
            raise GateFailure(f"capture is incomplete: {event}")
        for field in ("observed_bytes", "captured_bytes", "forwarded_bytes"):
            if int(event[field]) != source.size:
                raise GateFailure(f"capture {field} mismatch: {event}")
        if event.get("sha256") != source.sha256:
            raise GateFailure(f"capture hash mismatch: {event}")
        if event.get("content_encoding") != source.content_encoding:
            raise GateFailure(f"capture encoding mismatch: {event}")
        self._verify_artifact(event)
        self._assert_queue_bounds(event)

    def _assert_self_consistent_capture(self, event: dict[str, Any]) -> None:
        if event.get("body_state") != "streamed_complete":
            raise GateFailure(f"small response capture failed: {event}")
        if int(event["observed_bytes"]) != int(event["captured_bytes"]):
            raise GateFailure(f"small response byte mismatch: {event}")
        if int(event["observed_bytes"]) != int(event["forwarded_bytes"]):
            raise GateFailure(f"small response forwarding mismatch: {event}")
        self._verify_artifact(event)
        self._assert_queue_bounds(event)

    @staticmethod
    def _assert_queue_bounds(event: dict[str, Any]) -> None:
        if int(event["queue_peak_bytes"]) > int(event["queue_capacity_bytes"]):
            raise GateFailure(f"queue byte cap exceeded: {event}")
        if int(event["queue_peak_frames"]) > int(event["queue_capacity_frames"]):
            raise GateFailure(f"queue frame cap exceeded: {event}")

    @staticmethod
    def _verify_artifact(event: dict[str, Any]) -> None:
        artifact_text = event.get("artifact_path")
        if not isinstance(artifact_text, str):
            raise GateFailure(f"capture artifact is missing: {event}")
        artifact = Path(artifact_text)
        size, digest = hash_file(artifact)
        if size != int(event["captured_bytes"]) or digest != event.get("sha256"):
            raise GateFailure(f"artifact verification failed: {event}")
        if stat.S_IMODE(artifact.stat().st_mode) != 0o600:
            raise GateFailure(f"artifact mode is not 0600: {artifact}")

    @staticmethod
    def _require_sampler(proxy: ProxyProcess) -> RssSampler:
        if proxy.sampler is None:
            raise RuntimeError("RSS sampler missing")
        return proxy.sampler

    def _evaluate_global_assertions(self) -> None:
        case_names = {case["name"] for case in self.cases}
        required = {
            "http-50m-upload-content-length-pass",
            "http-50m-download-content-length-pass",
            "https-50m-upload-content-length-pass",
            "https-50m-download-content-length-pass",
            "http-upload-chunked-pass",
            "http-download-small-chunked-pass",
            "http-download-small-close-pass",
            "http-download-gzip-length-pass",
            "http-download-brotli-chunked-pass",
            "early-413-response-before-request-complete",
            "response-connection-truncated",
            "queue-full-pass",
            "writer-crash-pass",
            "enospc-pass",
            "http-50m-upload-content-length-strict",
            "http-50m-download-content-length-strict",
            "writer-crash-strict",
        }
        self.assertions["required_matrix_complete"] = required <= case_names
        self.assertions["large_fixture_is_50_mib"] = self.large_size == 50 * MIB
        self.assertions["all_proxy_listeners_loopback"] = all(
            proxy["listeners"]
            and all(listener["host"] == "127.0.0.1" for listener in proxy["listeners"])
            for proxy in self.proxies
        )
        self.assertions["worker_incremental_rss_within_32_mib"] = all(
            int(proxy["incremental_rss_kib"]) <= RSS_LIMIT_KIB for proxy in self.proxies
        )
        self.assertions["all_cases_recorded"] = len(self.cases) >= len(required)


def upload_via_proxy(
    proxy: ProxyProcess,
    *,
    scheme: str,
    target_port: int,
    source: FixtureFile,
    framing: str,
    ssl_context: ssl.SSLContext | None,
    allow_error: bool = False,
) -> ClientResult:
    token = uuid.uuid4().hex
    path = f"/upload?token={token}"
    connection, target = make_connection(
        proxy,
        scheme,
        target_port,
        path,
        ssl_context,
        timeout_seconds=5.0 if allow_error else 30.0,
    )
    digest = hashlib.sha256()
    sent = 0
    started = time.perf_counter()
    status: int | None = None
    response_json: dict[str, Any] | None = None
    error: str | None = None
    try:
        connection.putrequest("POST", target)
        connection.putheader("Content-Type", "application/octet-stream")
        if framing == "length":
            connection.putheader("Content-Length", str(source.size))
        elif framing == "chunked":
            connection.putheader("Transfer-Encoding", "chunked")
        else:
            raise ValueError(f"unsupported upload framing: {framing}")
        connection.endheaders()
        with source.path.open("rb", buffering=0) as input_file:
            while chunk := input_file.read(IO_CHUNK):
                if framing == "chunked":
                    connection.send(f"{len(chunk):x}\r\n".encode())
                    connection.send(chunk)
                    connection.send(b"\r\n")
                else:
                    connection.send(chunk)
                digest.update(chunk)
                sent += len(chunk)
        if framing == "chunked":
            connection.send(b"0\r\n\r\n")
        response = connection.getresponse()
        status = response.status
        body = response.read()
        if body:
            decoded = json.loads(body)
            if isinstance(decoded, dict):
                response_json = decoded
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as caught:
        error = describe_exception(caught)
        if not allow_error:
            raise GateFailure(f"upload failed: {error}") from caught
    finally:
        connection.close()
    return ClientResult(
        status=status,
        body_bytes=source.size,
        sha256=digest.hexdigest(),
        elapsed_seconds=time.perf_counter() - started,
        sent_bytes=sent,
        response_json=response_json,
        error=error,
        token=token,
    )


def download_via_proxy(
    proxy: ProxyProcess,
    *,
    scheme: str,
    target_port: int,
    source: FixtureFile,
    framing: str,
    ssl_context: ssl.SSLContext | None,
) -> ClientResult:
    path = f"/body/{source.name}?framing={framing}"
    connection, target = make_connection(proxy, scheme, target_port, path, ssl_context)
    digest = hashlib.sha256()
    received = 0
    status: int | None = None
    encoding: str | None = None
    declared_length: int | None = None
    error: str | None = None
    started = time.perf_counter()
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        status = response.status
        encoding = response.getheader("Content-Encoding")
        declared_text = response.getheader("Content-Length")
        if declared_text is not None:
            with suppress(ValueError):
                declared_length = int(declared_text, 10)
        try:
            while chunk := response.read(IO_CHUNK):
                digest.update(chunk)
                received += len(chunk)
        except http.client.IncompleteRead as caught:
            if caught.partial:
                digest.update(caught.partial)
                received += len(caught.partial)
            error = describe_exception(caught)
        if error is None and declared_length is not None and received != declared_length:
            error = f"content_length_mismatch:expected={declared_length},actual={received}"
    except (OSError, http.client.HTTPException) as caught:
        error = describe_exception(caught)
    finally:
        connection.close()
    return ClientResult(
        status=status,
        body_bytes=received,
        sha256=digest.hexdigest(),
        elapsed_seconds=time.perf_counter() - started,
        content_encoding=encoding,
        error=error,
    )


def simple_get(proxy: ProxyProcess, target_port: int, path: str) -> ClientResult:
    connection, target = make_connection(proxy, "http", target_port, path, None)
    started = time.perf_counter()
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        body = response.read()
        return ClientResult(
            status=response.status,
            body_bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            elapsed_seconds=time.perf_counter() - started,
        )
    finally:
        connection.close()


def early_413_via_proxy(proxy: ProxyProcess, target_port: int) -> tuple[bytes, int]:
    declared = 8 * MIB
    token = uuid.uuid4().hex
    headers = (
        f"POST http://127.0.0.1:{target_port}/early413?token={token} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target_port}\r\n"
        f"Content-Length: {declared}\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    prefix = b"e" * IO_CHUNK
    response = bytearray()
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(headers)
        client.sendall(prefix)
        while len(response) < 64 * 1024:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if b"early" in response:
                break
    return bytes(response), len(prefix)


def make_connection(
    proxy: ProxyProcess,
    scheme: str,
    target_port: int,
    path: str,
    ssl_context: ssl.SSLContext | None,
    *,
    timeout_seconds: float = 30.0,
) -> tuple[http.client.HTTPConnection, str]:
    if scheme == "http":
        connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=timeout_seconds)
        return connection, f"http://127.0.0.1:{target_port}{path}"
    if scheme == "https":
        if ssl_context is None:
            raise ValueError("HTTPS proxy request requires a client trust context")
        connection = http.client.HTTPSConnection(
            "127.0.0.1", proxy.port, timeout=timeout_seconds, context=ssl_context
        )
        connection.set_tunnel("127.0.0.1", target_port)
        return connection, path
    raise ValueError(f"unsupported scheme: {scheme}")


def one_direction(events: list[dict[str, Any]], direction: str) -> dict[str, Any]:
    matches = [event for event in events if event.get("direction") == direction]
    if len(matches) != 1:
        raise GateFailure(f"expected one {direction} final event, got {matches}")
    return matches[0]


def wait_for_upload_result(
    state: FixtureState, token: str, *, timeout_seconds: float = 5.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with state.lock:
            result = state.uploads.get(token)
            if result is not None:
                return dict(result)
        time.sleep(0.02)
    raise GateFailure(f"fixture did not record upload token {token}")


def sanitize_capture_event(event: dict[str, Any]) -> dict[str, Any]:
    kept = dict(event)
    for field in ("artifact_path", "partial_path"):
        value = kept.get(field)
        if isinstance(value, str):
            kept[field] = Path(value).name
    kept.pop("started_monotonic", None)
    kept.pop("finished_monotonic", None)
    return kept


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def process_tree_rss_kib(root_pid: int) -> int:
    total = 0
    pending = [root_pid]
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        status = Path(f"/proc/{pid}/status")
        try:
            for line in status.read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1])
                    break
            children_path = Path(f"/proc/{pid}/task/{pid}/children")
            if children_path.exists():
                pending.extend(int(value) for value in children_path.read_text().split())
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            continue
    return total


def listeners_owned_by_pid(pid: int, port: int) -> list[dict[str, Any]]:
    inodes: set[str] = set()
    fd_dir = Path(f"/proc/{pid}/fd")
    for fd in fd_dir.iterdir():
        with suppress(OSError):
            target = os.readlink(fd)
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
    listeners: list[dict[str, Any]] = []
    for table, ipv6 in ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True)):
        for line in table.read_text().splitlines()[1:]:
            columns = line.split()
            if len(columns) < 10 or columns[3] != "0A" or columns[9] not in inodes:
                continue
            address_text, port_hex = columns[1].split(":")
            if int(port_hex, 16) != port:
                continue
            if ipv6:
                host = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(address_text))
            else:
                host = socket.inet_ntoa(bytes.fromhex(address_text)[::-1])
            listeners.append({"host": host, "port": port, "inode": columns[9]})
    return listeners


def describe_exception(error: BaseException) -> str:
    message = str(error).replace("\n", " ")[:2000]
    return f"{type(error).__name__}:{message}"


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
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
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir", type=Path, default=SPIKE_ROOT / "evidence", help="output directory"
    )
    parser.add_argument("--large-mib", type=int, default=50)
    parser.add_argument("--small-mib", type=int, default=2)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.large_mib <= 0 or args.small_mib <= 0:
        raise SystemExit("fixture sizes must be positive")
    evidence_dir = args.evidence_dir.resolve()
    runner = GateRunner(large_size=args.large_mib * MIB, small_size=args.small_mib * MIB)
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory(prefix="flagdeck-mitm-r0-") as temporary:
            runtime_root = Path(temporary)
            os.chmod(runtime_root, 0o700)
            results = runner.run(runtime_root)
        results["gate_duration_seconds"] = time.perf_counter() - started
        write_private_json(evidence_dir / "results.json", results)
        summary = {
            "schema": results["schema"],
            "status": results["status"],
            "gate_duration_seconds": results["gate_duration_seconds"],
            "assertions": results["assertions"],
            "proxies": results["proxies"],
            "case_count": len(results["cases"]),
        }
        write_private_json(evidence_dir / "summary.json", summary)
        (evidence_dir / "failure.json").unlink(missing_ok=True)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except BaseException as error:
        failure = {
            "schema": "flagdeck.mitm-streaming-r0.v1",
            "status": "FAIL",
            "gate_duration_seconds": time.perf_counter() - started,
            "error": describe_exception(error),
            "completed_cases": runner.cases,
            "proxies": runner.proxies,
            "assertions": runner.assertions,
        }
        write_private_json(evidence_dir / "failure.json", failure)
        print(json.dumps(failure, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
