from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.fedora_lifecycle_gate import read_command
from scripts.finalize_release import validate_fedora_lifecycle


ROOT = Path(__file__).resolve().parents[2]


class FirstStableGateTests(unittest.TestCase):
    def test_optional_host_command_uses_fallback_when_unavailable(self) -> None:
        self.assertEqual(
            read_command(["flagdeck-command-that-does-not-exist"], "unknown"),
            "unknown",
        )

    def test_v1_workflow_selects_first_release_lifecycle(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/stable-release.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("if: inputs.tag != 'v1.0.0'", workflow)
        self.assertIn("--first-release", workflow)

    def test_stable_workflow_prepares_release_resources_before_source_gates(
        self,
    ) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/stable-release.yml"
        ).read_text(encoding="utf-8")

        preparation = workflow.index("mise run stage-host-runtime")
        self.assertIn("mise run r7-sbom", workflow)
        self.assertLess(preparation, workflow.index("mise run test-all"))

    def test_stable_build_uses_the_proven_ci_runner(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/stable-release.yml"
        ).read_text(encoding="utf-8")
        build_job = workflow[workflow.index("  build:") : workflow.index("  sign:")]

        self.assertIn("runs-on: ubuntu-24.04", build_job)

    def test_validation_job_runs_the_build_runner_that_produced_the_binary(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/stable-release.yml"
        ).read_text(encoding="utf-8")
        build_job = workflow[workflow.index("  build:") : workflow.index("  sign:")]
        validate_job = workflow[workflow.index("  validate-and-publish:") :]

        self.assertIn("TAURI_BINARY=", validate_job)
        build_runner = next(
            line.strip() for line in build_job.splitlines() if "runs-on:" in line
        )
        validate_runner = next(
            line.strip() for line in validate_job.splitlines() if "runs-on:" in line
        )
        self.assertEqual(validate_runner, build_runner)

    def test_package_structure_check_reads_listings_without_broken_pipes(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/stable-release.yml"
        ).read_text(encoding="utf-8")
        build_job = workflow[workflow.index("  build:") : workflow.index("  sign:")]

        self.assertNotIn('--contents "$deb" | grep', build_job)
        self.assertNotIn('-qpl "$rpm_package" | grep', build_job)
        self.assertIn('--contents "$deb" > deb-contents.txt', build_job)
        self.assertIn('-qpl "$rpm_package" > rpm-contents.txt', build_job)

    def test_preview_packages_trigger_only_accepts_prerelease_tags(self) -> None:
        workflow = (
            Path(__file__).parents[2] / ".github/workflows/packages.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('- "v*-*"', workflow)
        self.assertNotIn('- "v*"\n', workflow)

    def test_first_release_emits_explicit_not_applicable_upgrade_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            new_rpm = fixture_root / "FlagDeck-1.0.0-1.x86_64.rpm"
            public_key = fixture_root / "FlagDeck-1.0.0-signing-key.asc"
            output = fixture_root / "fedora-lifecycle.json"
            new_rpm.write_bytes(b"stable-rpm-fixture")
            public_key.write_bytes(b"public-key-fixture")

            shim_root = fixture_root / "bin"
            shim_root.mkdir()
            podman = shim_root / "podman"
            podman.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  echo sha256:first-stable-fixture\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            podman.chmod(0o700)
            environment = os.environ.copy()
            environment["PATH"] = f"{shim_root}:{environment['PATH']}"

            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/fedora_lifecycle_gate.py",
                    "--first-release",
                    "--new-rpm",
                    str(new_rpm),
                    "--public-key",
                    str(public_key),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["mode"], "first-release")
            self.assertEqual(report["status"], "not_applicable")
            self.assertEqual(
                report["reason"],
                "no prior stable RPM release exists",
            )
            self.assertTrue(report["passed"])
            self.assertIsNone(report["artifacts"]["previousRpmSha256"])
            self.assertEqual(
                set(report["records"]),
                {
                    "baseEnvironment",
                    "desktopValidator",
                    "importReleaseKey",
                    "installStable",
                    "verifyStable",
                    "removeStable",
                    "verifyRemoved",
                },
            )

    def test_finalizer_accepts_only_hash_bound_first_release_evidence(self) -> None:
        rpm_hash = "a" * 64
        public_key_hash = "b" * 64
        evidence = {
            "mode": "first-release",
            "status": "not_applicable",
            "reason": "no prior stable RPM release exists",
            "passed": True,
            "failure": None,
            "artifacts": {
                "previousRpmSha256": None,
                "stableRpmSha256": rpm_hash,
                "publicKeySha256": public_key_hash,
            },
            "records": {
                name: {"passed": True}
                for name in {
                    "baseEnvironment",
                    "desktopValidator",
                    "importReleaseKey",
                    "installStable",
                    "verifyStable",
                    "removeStable",
                    "verifyRemoved",
                }
            },
        }

        self.assertEqual(
            validate_fedora_lifecycle(evidence, rpm_hash, public_key_hash),
            "not_applicable",
        )

        invalid_cases = {
            "wrong mode": ("mode", "upgrade"),
            "wrong status": ("status", "PASS"),
            "wrong reason": ("reason", "missing prior package"),
            "previous hash present": (
                "artifacts.previousRpmSha256",
                "c" * 64,
            ),
            "stable hash mismatch": (
                "artifacts.stableRpmSha256",
                "d" * 64,
            ),
            "public key hash mismatch": (
                "artifacts.publicKeySha256",
                "e" * 64,
            ),
            "missing record": ("records.verifyRemoved", None),
        }
        for name, (path, replacement) in invalid_cases.items():
            with self.subTest(name=name):
                invalid = deepcopy(evidence)
                parent = invalid
                segments = path.split(".")
                for segment in segments[:-1]:
                    parent = parent[segment]
                if replacement is None:
                    parent.pop(segments[-1])
                else:
                    parent[segments[-1]] = replacement
                with self.assertRaises(RuntimeError):
                    validate_fedora_lifecycle(invalid, rpm_hash, public_key_hash)


if __name__ == "__main__":
    unittest.main()
