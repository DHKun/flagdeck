#!/usr/bin/env python3
"""Exercise the signed RPM through a clean Fedora install lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run(arguments: list[str], *, check: bool = False) -> dict[str, Any]:
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    record = {
        "command": arguments,
        "exitCode": result.returncode,
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return record


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def read_command(arguments: list[str], fallback: str) -> str:
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip() or fallback


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-rpm", type=Path, required=True)
    parser.add_argument("--new-rpm", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="registry.fedoraproject.org/fedora:44")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    old_rpm = (root / arguments.old_rpm).resolve()
    new_rpm = (root / arguments.new_rpm).resolve()
    public_key = (root / arguments.public_key).resolve()
    output = (root / arguments.output).resolve()
    for required in (old_rpm, new_rpm, public_key):
        if not required.is_file():
            raise FileNotFoundError(required)

    staging = output.parent / "lifecycle-input"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, mode=0o700)
    staged_old = staging / "FlagDeck-0.6.0-1.x86_64.rpm"
    staged_new = staging / "FlagDeck-1.0.0-1.x86_64.rpm"
    staged_key = staging / "FlagDeck-1.0.0-signing-key.asc"
    shutil.copy2(old_rpm, staged_old)
    shutil.copy2(new_rpm, staged_new)
    shutil.copy2(public_key, staged_key)

    pull = run(["podman", "pull", arguments.image], check=True)
    image = run(
        [
            "podman",
            "image",
            "inspect",
            arguments.image,
            "--format",
            "{{.Id}}",
        ],
        check=True,
    )["stdout"].strip()
    container = f"flagdeck-r7-lifecycle-{os.getpid()}"
    create = run(
        [
            "podman",
            "run",
            "--detach",
            "--name",
            container,
            "--volume",
            f"{staging}:/release:ro,Z",
            arguments.image,
            "sleep",
            "infinity",
        ],
        check=True,
    )
    records: dict[str, dict[str, Any]] = {}
    failure: str | None = None

    def execute(name: str, command: str) -> None:
        record = run(
            ["podman", "exec", container, "bash", "-euo", "pipefail", "-c", command]
        )
        records[name] = record
        if not record["passed"]:
            raise RuntimeError(
                f"lifecycle step {name} failed\n{record['stdout']}\n{record['stderr']}"
            )

    cleanup = {"passed": False, "exitCode": 1, "stdout": "", "stderr": ""}
    try:
        execute(
            "baseEnvironment",
            "cat /etc/fedora-release; uname -m; getenforce 2>/dev/null || true",
        )
        execute(
            "desktopValidator",
            "dnf install -y --setopt=install_weak_deps=False desktop-file-utils",
        )
        execute(
            "installPrevious",
            "dnf install -y --setopt=install_weak_deps=False "
            "/release/FlagDeck-0.6.0-1.x86_64.rpm",
        )
        execute(
            "verifyPrevious",
            "test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' flag-deck)\" = '0.6.0-1'; "
            "test -x /usr/bin/flagdeck-desktop",
        )
        execute(
            "importReleaseKey",
            "rpmkeys --import /release/FlagDeck-1.0.0-signing-key.asc; "
            "rpmkeys --checksig --verbose /release/FlagDeck-1.0.0-1.x86_64.rpm",
        )
        execute(
            "upgradeStable",
            "dnf install -y --setopt=install_weak_deps=False "
            "--setopt=localpkg_gpgcheck=True "
            "/release/FlagDeck-1.0.0-1.x86_64.rpm",
        )
        execute(
            "verifyStable",
            "test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' flag-deck)\" = '1.0.0-1'; "
            "desktop-file-validate /usr/share/applications/FlagDeck.desktop; "
            "test -x /usr/bin/flagdeck-adapter-metasploit; "
            "test -x /usr/bin/flagdeck-msf-credential-launcher; "
            "test -f /usr/lib/FlagDeck/LICENSE; "
            "test -f /usr/lib/FlagDeck/THIRD_PARTY.md; "
            "test -f /usr/lib/FlagDeck/flagdeck-1.0.0.cdx.json; "
            "test -f /usr/lib/FlagDeck/config/tools.toml; "
            "if ldd /usr/bin/flagdeck-desktop | grep -q 'not found'; then exit 1; fi",
        )
        execute(
            "rollbackPrevious",
            "dnf downgrade -y --setopt=install_weak_deps=False "
            "/release/FlagDeck-0.6.0-1.x86_64.rpm; "
            "test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' flag-deck)\" = '0.6.0-1'",
        )
        execute(
            "upgradeStableAgain",
            "dnf install -y --setopt=install_weak_deps=False "
            "--setopt=localpkg_gpgcheck=True "
            "/release/FlagDeck-1.0.0-1.x86_64.rpm; "
            "test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' flag-deck)\" = '1.0.0-1'",
        )
        execute(
            "removeStable",
            "dnf remove -y --no-autoremove flag-deck; "
            "for path in /usr/bin/flagdeck-desktop /usr/lib/FlagDeck "
            "/usr/share/applications/FlagDeck.desktop; do "
            'if test -e "$path"; then echo "residual:$path"; '
            'find "$path" -maxdepth 2 -print 2>/dev/null || true; exit 1; fi; done',
        )
        execute(
            "verifyRemoved",
            "if rpm -q flag-deck; then exit 1; fi; "
            "test ! -e /usr/bin/flagdeck-adapter-metasploit; "
            "test ! -e /usr/bin/flagdeck-msf-credential-launcher",
        )
    except RuntimeError as error:
        failure = str(error)
    finally:
        cleanup = run(["podman", "rm", "--force", container])

    passed = (
        failure is None
        and all(record["passed"] for record in records.values())
        and cleanup["passed"]
    )
    report = {
        "schema": "flagdeck.fedora-lifecycle.r7.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "passed": passed,
        "failure": failure,
        "host": {
            "platform": platform.platform(),
            "fedora": read_command(["cat", "/etc/fedora-release"], "unknown"),
            "desktop": os.environ.get("XDG_CURRENT_DESKTOP", "unknown"),
            "session": os.environ.get("XDG_SESSION_TYPE", "unknown"),
            "selinux": read_command(["getenforce"], "unknown"),
        },
        "container": {
            "image": arguments.image,
            "imageId": image,
            "pull": pull,
            "create": create,
            "cleanup": cleanup,
        },
        "artifacts": {
            "previousRpmSha256": sha256(staged_old),
            "stableRpmSha256": sha256(staged_new),
            "publicKeySha256": sha256(staged_key),
        },
        "records": records,
    }
    atomic_json(output, report)
    print(f"Fedora lifecycle {'PASS' if passed else 'FAIL'}: {output}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
