from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.finalize_release import (
    APPROVED_SIGNING_FINGERPRINT,
    ARTIFACTS,
    GUI_ASSERTIONS,
    public_key_fingerprint,
)
from scripts.finalize_release import (
    header_signature_verified as finalizer_header_signature_verified,
)
from scripts.run_release_audits import (
    LOCKED_CARGO_TOOLS,
    ensure_locked_cargo_tool,
)
from scripts.sign_rpm import (
    header_signature_verified,
    normalize_fingerprint,
    primary_fingerprints,
)


RPM_4_17_SIGNED = """/build/FlagDeck-1.0.0-1.x86_64.rpm:
    Header V4 RSA/SHA512 Signature, key ID 45873de6: OK
    Header SHA256 digest: OK
    Header SHA1 digest: OK
    Payload SHA256 digest: OK
    MD5 digest: OK
"""
RPM_4_18_SIGNED = RPM_4_17_SIGNED
RPM_6_SIGNED = """/build/FlagDeck-1.0.0-1.x86_64.rpm:
    Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: \
18ad547a9abcbc8b633031213fb7c61845873de6: OK
    Header SHA256 digest: OK
    Payload SHA256 digest: OK
"""
RPM_UNSIGNED = """/build/FlagDeck-1.0.0-1.x86_64.rpm:
    Header SHA256 digest: OK
    Header SHA1 digest: OK
    Payload SHA256 digest: OK
    MD5 digest: OK
"""
RPM_SIGNATURE_NOT_OK = """/build/FlagDeck-1.0.0-1.x86_64.rpm:
    Header V4 RSA/SHA512 Signature, key ID 45873de6: NOKEY
    Header SHA256 digest: OK
"""


ROOT = Path(__file__).resolve().parents[2]


class SigningToolsTests(unittest.TestCase):
    def test_normalizes_approved_fingerprint(self) -> None:
        value = f"  {APPROVED_SIGNING_FINGERPRINT.lower()}\n"
        self.assertEqual(
            normalize_fingerprint(value),
            APPROVED_SIGNING_FINGERPRINT,
        )

    def test_rejects_malformed_fingerprint(self) -> None:
        for value in ("", "A" * 39, "A" * 41, "Z" * 40):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_fingerprint(value)

    def test_primary_parser_excludes_signing_subkey_fingerprint(self) -> None:
        subkey_fingerprint = "A" * 40
        listing = "\n".join(
            [
                "sec:-:255:22:AAAA:0:0::::::: ",
                f"fpr:::::::::{APPROVED_SIGNING_FINGERPRINT}:",
                "ssb:-:255:18:BBBB:0:0::::::: ",
                f"fpr:::::::::{subkey_fingerprint}:",
            ]
        )
        self.assertEqual(
            primary_fingerprints(listing, "sec"),
            [APPROVED_SIGNING_FINGERPRINT],
        )

    def test_header_signature_check_spans_supported_rpm_wordings(self) -> None:
        accepted = {
            "rpm 4.17 (ubuntu-22.04)": RPM_4_17_SIGNED,
            "rpm 4.18 (ubuntu-24.04)": RPM_4_18_SIGNED,
            "rpm 6.0 (fedora 44)": RPM_6_SIGNED,
        }
        rejected = {
            "unsigned package": RPM_UNSIGNED,
            "signature not verified": RPM_SIGNATURE_NOT_OK,
            "empty output": "",
        }
        for name, verification in accepted.items():
            with self.subTest(name=name):
                self.assertTrue(header_signature_verified(verification))
                self.assertTrue(finalizer_header_signature_verified(verification))
        for name, verification in rejected.items():
            with self.subTest(name=name):
                self.assertFalse(header_signature_verified(verification))
                self.assertFalse(finalizer_header_signature_verified(verification))

    def test_committed_public_key_matches_approved_identity(self) -> None:
        self.assertEqual(
            public_key_fingerprint(ROOT / "release/FlagDeck-1.0.0-signing-key.asc"),
            APPROVED_SIGNING_FINGERPRINT,
        )

    def test_final_manifest_uses_reproducible_inputs(self) -> None:
        self.assertNotIn("PROJECT_PLAN.md", ARTIFACTS)
        self.assertNotIn("docs/R7_REPORT.md", ARTIFACTS)
        self.assertGreaterEqual(len(GUI_ASSERTIONS), 9)

    def test_release_audit_tools_are_version_pinned_and_reused(self) -> None:
        self.assertEqual(
            LOCKED_CARGO_TOOLS,
            {"cargo-audit": "0.22.2", "cargo-deny": "0.20.2"},
        )
        with TemporaryDirectory() as directory:
            tool_root = Path(directory)
            binary = tool_root / "bin/cargo-audit"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\necho 'cargo-audit 0.22.2'\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            self.assertEqual(
                ensure_locked_cargo_tool(tool_root, "cargo-audit", ROOT),
                binary,
            )


if __name__ == "__main__":
    unittest.main()
