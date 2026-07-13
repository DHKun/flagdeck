#!/usr/bin/env python3
"""Generate one release-wide CycloneDX SBOM from locked ecosystem metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_json(arguments: list[str], root: Path) -> dict[str, Any]:
    output = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(output.stdout)


def cargo_components(root: Path) -> list[dict[str, Any]]:
    metadata = command_json(
        ["cargo", "metadata", "--locked", "--format-version", "1"], root
    )
    components = []
    for package in metadata["packages"]:
        source = package.get("source")
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{package['name']}@{package['version']}",
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
            "properties": [
                {"name": "flagdeck:ecosystem", "value": "cargo"},
                {
                    "name": "flagdeck:source",
                    "value": source or "workspace-path",
                },
            ],
        }
        if package.get("license"):
            component["licenses"] = [
                {"expression": package["license"]}
            ]
        components.append(component)
    return components


def split_npm_key(key: str) -> tuple[str, str]:
    name, version = key.rsplit("@", 1)
    return name, version.split("(", 1)[0]


def npm_components(root: Path) -> list[dict[str, Any]]:
    lock = yaml.safe_load((root / "pnpm-lock.yaml").read_text(encoding="utf-8"))
    components = []
    for key, package in lock.get("packages", {}).items():
        name, version = split_npm_key(key)
        encoded_name = name.replace("@", "%40").replace("/", "%2F")
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:npm/{encoded_name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:npm/{encoded_name}@{version}",
            "properties": [
                {"name": "flagdeck:ecosystem", "value": "pnpm"},
            ],
        }
        integrity = package.get("resolution", {}).get("integrity")
        if integrity:
            component["properties"].append(
                {"name": "flagdeck:lock-integrity", "value": integrity}
            )
        components.append(component)
    return components


def python_components(root: Path) -> list[dict[str, Any]]:
    lock = tomllib.loads(
        (root / "workers/mitmproxy/uv.lock").read_text(encoding="utf-8")
    )
    components = []
    for package in lock.get("package", []):
        name = package["name"]
        version = package["version"]
        source = package.get("source", {})
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "properties": [
                    {"name": "flagdeck:ecosystem", "value": "uv"},
                    {
                        "name": "flagdeck:source",
                        "value": json.dumps(source, sort_keys=True),
                    },
                ],
            }
        )
    return components


def external_components(root: Path) -> list[dict[str, Any]]:
    tools = tomllib.loads((root / "config/tools.toml").read_text(encoding="utf-8"))
    launchers = tomllib.loads(
        (root / "config/external-launchers.toml").read_text(encoding="utf-8")
    )
    components = []
    for tool in tools.get("tool", []):
        components.append(
            {
                "type": "application",
                "bom-ref": f"flagdeck:external-tool:{tool['id']}@{tool['version']}",
                "name": tool["name"],
                "version": tool["version"],
                "hashes": [
                    {"alg": "SHA-256", "content": tool["pinned_sha256"]}
                ],
                "properties": [
                    {
                        "name": "flagdeck:distribution",
                        "value": tool["distribution"],
                    },
                    {"name": "flagdeck:pack", "value": tool["pack_id"]},
                    {
                        "name": "flagdeck:bundled-path",
                        "value": tool["bundled_path"],
                    },
                    {
                        "name": "flagdeck:integration-mode",
                        "value": tool["integration_mode"],
                    },
                    {"name": "flagdeck:license", "value": tool["license"]},
                    {"name": "flagdeck:risk-level", "value": tool["risk_level"]},
                    {
                        "name": "flagdeck:runtime-fingerprint",
                        "value": tool["runtime_fingerprint"],
                    },
                ],
            }
        )
    for launcher in launchers.get("launcher", []):
        components.append(
            {
                "type": "application",
                "bom-ref": (
                    f"flagdeck:external-launcher:{launcher['id']}@{launcher['version']}"
                ),
                "name": launcher["name"],
                "version": launcher["version"],
                "hashes": [
                    {"alg": "SHA-256", "content": launcher["program_sha256"]}
                ],
                "properties": [
                    {
                        "name": "flagdeck:distribution",
                        "value": launcher["distribution"],
                    },
                    {"name": "flagdeck:pack", "value": launcher["pack_id"]},
                    {"name": "flagdeck:path", "value": launcher["program"]},
                    {
                        "name": "flagdeck:integration-mode",
                        "value": launcher["integration_mode"],
                    },
                    {
                        "name": "flagdeck:license",
                        "value": launcher["license"],
                    },
                    {"name": "flagdeck:risk-level", "value": launcher["risk_level"]},
                    {"name": "flagdeck:capability", "value": launcher["capability"]},
                ],
            }
        )
    return components


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=False)
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
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    components = (
        cargo_components(root)
        + npm_components(root)
        + python_components(root)
        + external_components(root)
    )
    unique = {component["bom-ref"]: component for component in components}
    lockfiles = [
        "Cargo.lock",
        "pnpm-lock.yaml",
        "uv.lock",
        "workers/mitmproxy/uv.lock",
        "mise.lock",
    ]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "flagdeck-release-sbom-generator",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/flagdeck@{arguments.version}",
                "name": "FlagDeck",
                "version": arguments.version,
                "licenses": [{"license": {"id": "MIT"}}],
                "purl": f"pkg:generic/flagdeck@{arguments.version}",
            },
            "properties": [
                {"name": f"flagdeck:lock:{path}:sha256", "value": sha256(root / path)}
                for path in lockfiles
            ],
        },
        "components": sorted(unique.values(), key=lambda component: component["bom-ref"]),
    }
    write_private_json(arguments.output, sbom)
    print(f"CycloneDX SBOM: {arguments.output} ({len(unique)} components)")


if __name__ == "__main__":
    main()
