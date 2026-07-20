#!/usr/bin/env python3
"""Create an isolated release key, sign the RPM, and verify it independently."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import string
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


def primary_fingerprints(listing: str, record_type: str) -> list[str]:
    fingerprints: list[str] = []
    awaiting_fingerprint = False
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] == record_type:
            awaiting_fingerprint = True
        elif awaiting_fingerprint and fields[0] == "fpr":
            fingerprints.append(normalize_fingerprint(fields[9]))
            awaiting_fingerprint = False
    return fingerprints


def normalize_fingerprint(value: str) -> str:
    normalized = "".join(value.split()).upper()
    if len(normalized) != 40 or any(
        character not in string.hexdigits for character in normalized
    ):
        raise ValueError(
            "OpenPGP fingerprint must contain exactly 40 hexadecimal digits"
        )
    return normalized


def secret_fingerprints(gpg_home: Path) -> list[str]:
    result = run(
        [
            "gpg",
            "--batch",
            "--homedir",
            str(gpg_home),
            "--with-colons",
            "--fingerprint",
            "--list-secret-keys",
        ]
    )
    return primary_fingerprints(result.stdout, "sec")


def public_key_fingerprints(public_key: Path) -> list[str]:
    result = run(
        [
            "gpg",
            "--batch",
            "--with-colons",
            "--show-keys",
            str(public_key),
        ]
    )
    return primary_fingerprints(result.stdout, "pub")


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
    parser.add_argument(
        "--expected-fingerprint",
        help="require this approved 40-digit primary-key fingerprint",
    )
    parser.add_argument(
        "--allow-generate",
        action="store_true",
        help="generate a new signing identity for local development only",
    )
    parser.add_argument(
        "--replace-public-key",
        action="store_true",
        help="replace an existing public key; requires --allow-generate",
    )
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    rpm = (root / arguments.rpm).resolve()
    gpg_home = (root / arguments.gpg_home).resolve()
    public_key = (root / arguments.public_key).resolve()
    rpm_db = (root / arguments.rpm_db).resolve()
    evidence = (root / arguments.evidence).resolve()
    if not rpm.is_file():
        raise FileNotFoundError(rpm)
    if arguments.replace_public_key and not arguments.allow_generate:
        raise RuntimeError("--replace-public-key requires --allow-generate")

    gpg_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(gpg_home, 0o700)
    fingerprints = secret_fingerprints(gpg_home)
    if not fingerprints:
        if not arguments.allow_generate:
            raise RuntimeError(
                "release signing key is unavailable; import the approved key first"
            )
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
    expected_fingerprint = (
        normalize_fingerprint(arguments.expected_fingerprint)
        if arguments.expected_fingerprint
        else None
    )
    trusted_fingerprints = (
        []
        if arguments.replace_public_key or not public_key.is_file()
        else public_key_fingerprints(public_key)
    )
    candidates = set(fingerprints)
    if expected_fingerprint is not None:
        candidates &= {expected_fingerprint}
    if trusted_fingerprints:
        candidates &= set(trusted_fingerprints)
    if len(candidates) != 1:
        raise RuntimeError(
            "signing identity selection failed; import exactly one approved private key "
            "matching --expected-fingerprint and the existing public key"
        )
    fingerprint = candidates.pop()
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
