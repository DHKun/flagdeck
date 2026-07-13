#!/usr/bin/env python3
"""Run locked production dependency audits and preserve machine-readable evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACCEPTED_UNMAINTAINED_ADVISORIES = [
    "RUSTSEC-2024-0370",
    "RUSTSEC-2024-0411",
    "RUSTSEC-2024-0412",
    "RUSTSEC-2024-0413",
    "RUSTSEC-2024-0415",
    "RUSTSEC-2024-0416",
    "RUSTSEC-2024-0418",
    "RUSTSEC-2024-0419",
    "RUSTSEC-2024-0420",
    "RUSTSEC-2024-0429",
    "RUSTSEC-2025-0075",
    "RUSTSEC-2025-0080",
    "RUSTSEC-2025-0081",
    "RUSTSEC-2025-0098",
    "RUSTSEC-2025-0100",
]


def run(
    arguments: list[str],
    root: Path,
    *,
    input_text: str | None = None,
    accepted_codes: set[int] | None = None,
) -> dict[str, Any]:
    result = subprocess.run(
        arguments,
        cwd=root,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    accepted = accepted_codes or {0}
    return {
        "command": arguments,
        "exitCode": result.returncode,
        "passed": result.returncode in accepted,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def parse_json_output(record: dict[str, Any]) -> Any:
    text = record["stdout"].strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
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
    parser.add_argument("--tool-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    cargo_audit = arguments.tool_root / "bin/cargo-audit"
    cargo_deny = arguments.tool_root / "bin/cargo-deny"
    records: dict[str, dict[str, Any]] = {}
    cargo_audit_arguments = [
        str(cargo_audit),
        "audit",
        "--json",
        "--deny",
        "warnings",
    ]
    for advisory in ACCEPTED_UNMAINTAINED_ADVISORIES:
        cargo_audit_arguments.extend(["--ignore", advisory])
    records["cargoAudit"] = run(cargo_audit_arguments, root)
    records["cargoDeny"] = run(
        [
            str(cargo_deny),
            "--format",
            "json",
            "check",
            "advisories",
            "licenses",
            "sources",
        ],
        root,
    )
    records["cargoDuplicates"] = run(
        ["cargo", "tree", "--workspace", "--duplicates", "--locked"], root
    )
    records["pnpmProductionAudit"] = run(["pnpm", "audit", "--prod", "--json"], root)
    records["uvEnvironmentCheck"] = run(
        ["uv", "pip", "check", "--project", "workers/mitmproxy"], root
    )
    exported = run(
        [
            "uv",
            "export",
            "--project",
            "workers/mitmproxy",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        ],
        root,
    )
    records["uvLockedExport"] = exported
    if exported["passed"]:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".txt"
        ) as requirements:
            requirements.write(exported["stdout"])
            requirements.flush()
            records["pythonProductionAudit"] = run(
                [
                    "uvx",
                    "pip-audit",
                    "--require-hashes",
                    "--no-deps",
                    "--disable-pip",
                    "--format",
                    "json",
                    "--requirement",
                    requirements.name,
                ],
                root,
            )
    else:
        records["pythonProductionAudit"] = {
            "command": ["uvx", "pip-audit"],
            "exitCode": 1,
            "passed": False,
            "stdout": "",
            "stderr": "locked requirements export failed",
        }

    for record in records.values():
        parsed = parse_json_output(record)
        if parsed is not None:
            record["json"] = parsed
            record["stdout"] = ""
    passed = all(
        record["passed"]
        for name, record in records.items()
        if name != "cargoDuplicates"
    )
    report = {
        "schema": "flagdeck.release-audit.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "passed": passed,
        "acceptedUnmaintainedAdvisories": {
            "ids": ACCEPTED_UNMAINTAINED_ADVISORIES,
            "reason": (
                "Current Tauri 2 Linux GTK3/WebKitGTK and urlpattern transitive "
                "dependencies have no safe compatible upgrade; Fedora supplies "
                "the native runtime and locked dependencies remain reviewable."
            ),
        },
        "duplicateDependencyReviewRequired": bool(
            records["cargoDuplicates"]["stdout"].strip()
        ),
        "records": records,
    }
    write_private_json(arguments.output, report)
    print(f"Release audits {'PASS' if passed else 'FAIL'}: {arguments.output}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
