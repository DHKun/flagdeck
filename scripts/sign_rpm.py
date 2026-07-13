#!/usr/bin/env python3
"""Create an isolated release key, sign the RPM, and verify it independently."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run(
    arguments: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def secret_fingerprints(gpg_home: Path) -> list[str]:
    result = run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(gpg_home),
            "--with-colons",
            "--list-secret-keys",
        ]
    )
    return [
        line.split(":")[9]
        for line in result.stdout.splitlines()
        if line.startswith("fpr:")
    ]


def locate_rpmsign(root: Path) -> Path:
    installed = shutil.which("rpmsign")
    if installed:
        return Path(installed)
    extracted = root / ".release-tools/rpm-sign-root/usr/bin/rpmsign"
    if extracted.is_file():
        return extracted
    raise RuntimeError("rpmsign is unavailable; install the Fedora rpm-sign package")


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write(
        path,
        (json.dumps(value, indent=2) + "\n").encode(),
        0o600,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpm", type=Path, required=True)
    parser.add_argument("--gpg-home", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--rpm-db", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    rpm = (root / arguments.rpm).resolve()
    gpg_home = (root / arguments.gpg_home).resolve()
    public_key = (root / arguments.public_key).resolve()
    rpm_db = (root / arguments.rpm_db).resolve()
    evidence = (root / arguments.evidence).resolve()
    if not rpm.is_file():
        raise FileNotFoundError(rpm)

    gpg_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(gpg_home, 0o700)
    fingerprints = secret_fingerprints(gpg_home)
    if not fingerprints:
        run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(gpg_home),
                "--passphrase",
                "",
                "--quick-generate-key",
                "FlagDeck 1.0 Release <release@flagdeck.local>",
                "ed25519",
                "sign",
                "0",
            ]
        )
        fingerprints = secret_fingerprints(gpg_home)
    fingerprint = fingerprints[0]
    exported = subprocess.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(gpg_home),
            "--armor",
            "--export",
            fingerprint,
        ],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    atomic_write(public_key, exported, 0o644)

    rpmsign = locate_rpmsign(root)
    signing_environment = os.environ.copy()
    signing_environment["GNUPGHOME"] = str(gpg_home)
    run(
        [str(rpmsign), "--addsign", "--key-id", fingerprint, str(rpm)],
        env=signing_environment,
    )

    if rpm_db.exists():
        shutil.rmtree(rpm_db)
    rpm_db.mkdir(parents=True, mode=0o700)
    run(["rpmkeys", "--dbpath", str(rpm_db), "--import", str(public_key)])
    verification = run(
        [
            "rpmkeys",
            "--dbpath",
            str(rpm_db),
            "--checksig",
            "--verbose",
            str(rpm),
        ]
    )
    passed = "OpenPGP" in verification.stdout and ": OK" in verification.stdout
    report = {
        "schema": "flagdeck.rpm-signature.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "passed": passed,
        "rpm": str(rpm.relative_to(root)),
        "rpmSha256": sha256(rpm),
        "publicKey": str(public_key.relative_to(root)),
        "publicKeySha256": sha256(public_key),
        "fingerprint": fingerprint,
        "algorithm": "Ed25519",
        "rpmsignVersion": run([str(rpmsign), "--version"]).stdout.strip(),
        "verification": verification.stdout.strip(),
    }
    write_json(evidence, report)
    print(verification.stdout.strip())
    print(f"RPM signature {'PASS' if passed else 'FAIL'}: {evidence}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
