#!/usr/bin/env python3
"""Validate Stable evidence and emit a hash-bound release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACTS = [
    "target/release/bundle/rpm/FlagDeck-1.0.0-1.x86_64.rpm",
    "target/release/flagdeck-desktop",
    "release/FlagDeck-1.0.0-signing-key.asc",
    "release/evidence/flagdeck-1.0.0.cdx.json",
    "release/evidence/dependency-audits.json",
    "release/evidence/rpm-signature.json",
    "release/evidence/fedora-lifecycle.json",
    "tests/performance/baselines/r3-reliable-orchestration.json",
    "tests/performance/r4-mitmproxy/summary.json",
    "tests/performance/r5-metasploit/results.json",
    "tests/performance/r6-intruder-upload/results.json",
    "tests/performance/r7-stable/results.json",
    "tests/gui/evidence/summary.json",
    "tests/gui/evidence/desktop-memory.json",
    "Cargo.lock",
    "pnpm-lock.yaml",
    "workers/mitmproxy/uv.lock",
    "mise.lock",
    "LICENSE",
    "THIRD_PARTY.md",
    "PROJECT_PLAN.md",
    "docs/R7_REPORT.md",
    "docs/adr/0013-r7-stable-release-boundaries.md",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(root: Path, relative: str) -> dict[str, Any]:
    with (root / relative).open(encoding="utf-8") as source:
        return json.load(source)


def require_all_true(name: str, values: dict[str, Any]) -> None:
    failed = [key for key, value in values.items() if value is not True]
    if failed:
        raise RuntimeError(f"{name} failed assertions: {', '.join(failed)}")


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = (root / arguments.output).resolve()
    paths = {relative: root / relative for relative in ARTIFACTS}
    missing = [relative for relative, path in paths.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(", ".join(missing))

    rpm_path = paths[ARTIFACTS[0]]
    binary_path = paths[ARTIFACTS[1]]
    rpm_hash = sha256(rpm_path)
    binary_hash = sha256(binary_path)
    audits = read_json(root, "release/evidence/dependency-audits.json")
    signature = read_json(root, "release/evidence/rpm-signature.json")
    lifecycle = read_json(root, "release/evidence/fedora-lifecycle.json")
    performance = read_json(root, "tests/performance/r7-stable/results.json")
    gui = read_json(root, "tests/gui/evidence/summary.json")
    memory = read_json(root, "tests/gui/evidence/desktop-memory.json")
    sbom = read_json(root, "release/evidence/flagdeck-1.0.0.cdx.json")

    if audits.get("passed") is not True:
        raise RuntimeError("dependency audit evidence failed")
    if signature.get("passed") is not True or signature.get("rpmSha256") != rpm_hash:
        raise RuntimeError("RPM signature evidence is stale")
    if lifecycle.get("passed") is not True or (
        lifecycle.get("artifacts", {}).get("stableRpmSha256") != rpm_hash
    ):
        raise RuntimeError("Fedora lifecycle evidence is stale")
    require_all_true("R7 performance", performance.get("assertions", {}))
    if gui.get("status") != "PASS" or gui.get("packageSha256") != rpm_hash:
        raise RuntimeError("GUI release evidence is stale")
    if gui.get("applicationSha256") != binary_hash:
        raise RuntimeError("GUI binary evidence is stale")
    if memory.get("status") != "PASS" or memory.get("applicationSha256") != binary_hash:
        raise RuntimeError("desktop memory evidence is stale")
    require_all_true("desktop memory", memory.get("assertions", {}))
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        raise RuntimeError("SBOM format validation failed")

    metadata_text = subprocess.run(
        [
            "rpm",
            "-qp",
            "--qf",
            "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SIZE}\n",
            str(rpm_path),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    name, version, release, architecture, installed_bytes = metadata_text.split("\t")
    if (name, version, release, architecture) != (
        "flag-deck",
        "1.0.0",
        "1",
        "x86_64",
    ):
        raise RuntimeError(f"unexpected RPM metadata: {metadata_text}")

    ecosystem_counts: dict[str, int] = {}
    for component in sbom.get("components", []):
        for property_value in component.get("properties", []):
            if property_value.get("name") == "flagdeck:ecosystem":
                ecosystem = property_value["value"]
                ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
    external_count = len(sbom.get("components", [])) - sum(ecosystem_counts.values())
    if external_count:
        ecosystem_counts["external"] = external_count
    report = {
        "schema": "flagdeck.release-manifest.r7.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "PASS",
        "product": {
            "name": "FlagDeck",
            "version": "1.0.0",
            "target": "Fedora 44 x86_64",
        },
        "rpm": {
            "name": name,
            "version": version,
            "release": release,
            "architecture": architecture,
            "compressedBytes": rpm_path.stat().st_size,
            "installedBytes": int(installed_bytes),
            "sha256": rpm_hash,
            "signingFingerprint": signature["fingerprint"],
        },
        "sbom": {
            "format": "CycloneDX 1.6",
            "components": len(sbom.get("components", [])),
            "ecosystemCounts": ecosystem_counts,
        },
        "checks": {
            "dependencyAudits": True,
            "rpmSignature": True,
            "fedoraLifecycle": True,
            "performance": True,
            "guiSecurity": True,
            "desktopMemory": True,
        },
        "artifacts": [
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for relative, path in paths.items()
        ],
    }
    atomic_json(output, report)
    print(f"FlagDeck Stable release manifest PASS: {output}")


if __name__ == "__main__":
    main()
