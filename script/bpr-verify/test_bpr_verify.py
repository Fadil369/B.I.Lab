#!/usr/bin/env python3
"""Unit tests for script/bpr-verify/bpr_verify.py.

Generates ephemeral Root + Issuing X.509 CA chains via ``openssl`` inside temporary
directories and exercises PKI verification, DER/PEM fingerprint parity, expiry thresholds,
FHIR R4 / NPHIES Saudi ID & Iqama Luhn validation, ``NOT_ASSESSED`` neutral trust governance,
and unmasked PHI heuristics.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bpr_verify  # noqa: E402


def make_saudi_id(prefix: str, body8: str) -> str:
    """Build a synthetic 10-digit Saudi ID / Iqama dynamically with a valid Luhn check digit."""
    assert prefix in ("1", "2") and len(body8) == 8 and body8.isdigit()
    stem = prefix + body8
    total = 0
    for idx, ch in enumerate(stem):
        d = int(ch)
        if idx % 2 == 0:
            doubled = d * 2
            total += doubled // 10 + doubled % 10
        else:
            total += d
    check = (10 - (total % 10)) % 10
    return stem + str(check)


def _openssl(args: list[str], cwd: Path) -> None:
    proc = subprocess.run(
        ["openssl", *args],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {proc.stderr.decode('utf-8', errors='replace')}")


def _cert_sha256_colon(pem_path: Path) -> str:
    der = subprocess.check_output(["openssl", "x509", "-in", str(pem_path), "-outform", "DER"])
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def create_test_pki(trust_dir: Path, root_days: int = 3650, issuing_days: int = 365) -> None:
    """Generate an ephemeral ECDSA P-256 BPR Root CA + Issuing CA hierarchy in ``trust_dir``."""
    trust_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        w = Path(work)
        ext_cfg = w / "ca.cnf"
        ext_cfg.write_text(
            "[root_ca]\n"
            "basicConstraints = critical,CA:true\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always\n"
            "[issuing_ca]\n"
            "basicConstraints = critical,CA:true,pathlen:0\n"
            "keyUsage = critical,digitalSignature,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always\n",
            encoding="utf-8",
        )
        _openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "root.key"], w)
        _openssl(
            [
                "req", "-new", "-x509", "-key", "root.key", "-sha256",
                "-days", str(root_days),
                "-subj", "/C=SA/O=BrainSAIT/OU=Provider Registry/CN=BPR Root CA",
                "-config", "ca.cnf", "-extensions", "root_ca",
                "-out", str(trust_dir / "bpr-root.pem"),
            ],
            w,
        )
        _openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "issuing.key"], w)
        _openssl(
            [
                "req", "-new", "-key", "issuing.key",
                "-subj", "/C=SA/O=BrainSAIT/OU=Provider Registry/CN=BPR Provider Issuing CA",
                "-out", "issuing.csr",
            ],
            w,
        )
        _openssl(
            [
                "x509", "-req", "-in", "issuing.csr",
                "-CA", str(trust_dir / "bpr-root.pem"),
                "-CAkey", "root.key", "-CAcreateserial", "-sha256",
                "-days", str(issuing_days),
                "-extfile", "ca.cnf", "-extensions", "issuing_ca",
                "-out", str(trust_dir / "bpr-issuing.pem"),
            ],
            w,
        )
        _openssl(
            [
                "x509", "-in", str(trust_dir / "bpr-root.pem"),
                "-outform", "DER", "-out", str(trust_dir / "bpr-root.cer"),
            ],
            w,
        )
        chain_text = (
            (trust_dir / "bpr-issuing.pem").read_text(encoding="utf-8")
            + (trust_dir / "bpr-root.pem").read_text(encoding="utf-8")
        )
        (trust_dir / "bpr-chain.pem").write_text(chain_text, encoding="utf-8")

        root_fp = _cert_sha256_colon(trust_dir / "bpr-root.pem")
        iss_fp = _cert_sha256_colon(trust_dir / "bpr-issuing.pem")
        (trust_dir / "fingerprints.txt").write_text(
            f"BPR Root CA        SHA-256: {root_fp}\n"
            f"BPR Issuing CA     SHA-256: {iss_fp}\n",
            encoding="utf-8",
        )


class SaudiIdTests(unittest.TestCase):
    def test_valid_national_id_and_iqama(self) -> None:
        nat_id = make_saudi_id("1", "04567891")
        iqama = make_saudi_id("2", "34567891")
        self.assertTrue(bpr_verify.saudi_id_luhn_valid(nat_id))
        self.assertTrue(bpr_verify.saudi_id_luhn_valid(iqama))

    def test_invalid_checksum_or_prefix_rejected(self) -> None:
        nat_id = make_saudi_id("1", "04567891")
        bad_digit = str((int(nat_id[-1]) + 1) % 10)
        corrupted = nat_id[:-1] + bad_digit
        self.assertFalse(bpr_verify.saudi_id_luhn_valid(corrupted))
        self.assertFalse(bpr_verify.saudi_id_luhn_valid("3000000000"))
        self.assertFalse(bpr_verify.saudi_id_luhn_valid("12345"))


class PkiTrustVerificationTests(unittest.TestCase):
    def test_valid_pki_hierarchy_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_test_pki(root / "trust", root_days=3650, issuing_days=365)
            report = bpr_verify.run_verification(root=root, trust_dir="trust", min_days=30)
            self.assertTrue(report.ok, msg=f"Unexpected issues: {report.issues}")
            self.assertEqual(report.certificates_checked, 5)  # root + issuing + 2 in chain + root.cer

    def test_expiry_below_min_days_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_test_pki(root / "trust", root_days=3650, issuing_days=10)
            report = bpr_verify.run_verification(root=root, trust_dir="trust", min_days=30)
            self.assertFalse(report.ok)
            rules = {i.rule for i in report.issues}
            self.assertIn("BPR-PKI-004", rules)

    def test_untrusted_issuing_cert_fails_chain_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as rogue_tmp:
            root = Path(tmp)
            rogue = Path(rogue_tmp)
            create_test_pki(root / "trust")
            create_test_pki(rogue / "trust")
            # Overwrite issuing CA with one signed by an unrelated root CA
            (root / "trust" / "bpr-issuing.pem").write_bytes((rogue / "trust" / "bpr-issuing.pem").read_bytes())
            report = bpr_verify.run_verification(root=root, trust_dir="trust", min_days=30)
            self.assertFalse(report.ok)
            rules = {i.rule for i in report.issues}
            self.assertIn("BPR-PKI-008", rules)

    def test_mismatched_der_root_cer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other_tmp:
            root = Path(tmp)
            other = Path(other_tmp)
            create_test_pki(root / "trust")
            create_test_pki(other / "trust")
            (root / "trust" / "bpr-root.cer").write_bytes((other / "trust" / "bpr-root.cer").read_bytes())
            report = bpr_verify.run_verification(root=root, trust_dir="trust", min_days=30)
            self.assertFalse(report.ok)
            self.assertIn("BPR-PKI-010", {i.rule for i in report.issues})


class FhirAndBprSchemaTests(unittest.TestCase):
    def test_valid_fhir_bundle_and_bpr_neutral_not_assessed_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fhir_dir = root / "fhir"
            fhir_dir.mkdir()
            valid_nid = make_saudi_id("1", "09876543")
            valid_iqama = make_saudi_id("2", "19876543")

            bundle = {
                "resource" + "Type": "Bundle",
                "type": "collection",
                "entry": [
                    {
                        "resource": {
                            "resource" + "Type": "Patient",
                            "id": "pat-synth-1",
                            "identifier": [
                                {"system": "http://nphies.sa/identifier/nationalid", "value": valid_nid}
                            ],
                            "telecom": [
                                {"system": "email", "value": "patient1@example.com"},
                                {"system": "phone", "value": "0500000000"},
                            ],
                        }
                    },
                    {
                        "resource": {
                            "resource" + "Type": "Practitioner",
                            "id": "SA-PHY-000001",
                            "identifier": [
                                {"system": "https://registry.brainsait.de/identifier/spid", "value": "SA-PHY-000001"}
                            ],
                            "active": True,
                        }
                    },
                ],
            }
            (fhir_dir / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

            provider_android = {
                "spid": "SA-PHY-000001",
                "name_en": "Synthetic Clinician",
                "profession": "physician",
                "licence_status": "NOT_ASSESSED",
                "enrollment_status": "APPROVED",
            }
            (fhir_dir / "provider-android.json").write_text(json.dumps(provider_android), encoding="utf-8")

            providers_web = {
                "items": [
                    {
                        "spid": "SA-PHY-000002",
                        "type": "physician",
                        "name_en": "Synthetic Doctor",
                        "verification": {
                            "credentials": "not_assessed",
                            "signature": "current",
                            "domain_ownership": "not_assessed",
                        },
                        "trust": {
                            "identity": "confirmed",
                            "signature": "current",
                            "membership": "active",
                            "licence": "not_assessed",
                            "qualifications": "not_assessed",
                            "privileges": "none",
                        },
                    }
                ]
            }
            (fhir_dir / "providers-web.json").write_text(json.dumps(providers_web), encoding="utf-8")

            bos_draft = {
                "patient_name_en": "Synthetic Resident",
                "national_id": valid_iqama,
                "pdpl_consent_accepted": True,
            }
            (fhir_dir / "bos-draft.json").write_text(json.dumps(bos_draft), encoding="utf-8")

            report = bpr_verify.run_verification(
                root=root, trust_dir=None, fhir_paths=["fhir"], require_trust=False, require_fhir=True
            )
            self.assertTrue(report.ok, msg=f"Unexpected issues: {report.issues}")
            self.assertEqual(report.fhir_resources_checked, 3)  # Bundle + Patient + Practitioner
            self.assertEqual(report.bpr_records_checked, 3)

    def test_invalid_nphies_luhn_and_wrong_prefix_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fhir_dir = root / "fhir"
            fhir_dir.mkdir()
            valid_iqama = make_saudi_id("2", "19876543")
            bad_nid = "104567891" + str((int(make_saudi_id("1", "04567891")[-1]) + 1) % 10)

            bad_patient = {
                "resource" + "Type": "Patient",
                "id": "pat-bad",
                "identifier": [
                    # Iqama prefix 2 under nationalid system -> BPR-NPHIES-002
                    {"system": "http://nphies.sa/identifier/nationalid", "value": valid_iqama},
                    # Invalid Luhn -> BPR-NPHIES-003
                    {"system": "http://nphies.sa/identifier/nationalid", "value": bad_nid},
                ],
            }
            (fhir_dir / "bad-patient.json").write_text(json.dumps(bad_patient), encoding="utf-8")
            report = bpr_verify.run_verification(
                root=root, trust_dir=None, fhir_paths=["fhir"], require_trust=False, require_fhir=True
            )
            self.assertFalse(report.ok)
            rules = {i.rule for i in report.issues}
            self.assertIn("BPR-NPHIES-002", rules)
            self.assertIn("BPR-NPHIES-003", rules)

    def test_non_neutral_trust_enum_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fhir_dir = root / "fhir"
            fhir_dir.mkdir()
            bad_provider = {
                "spid": "SA-PHY-000099",
                "name_en": "Test Provider",
                "profession": "physician",
                "licence_status": "UNTRUSTED",
                "trust": {"licence": "fake"},
            }
            (fhir_dir / "bad-provider.json").write_text(json.dumps(bad_provider), encoding="utf-8")
            report = bpr_verify.run_verification(
                root=root, trust_dir=None, fhir_paths=["fhir"], require_trust=False, require_fhir=True
            )
            self.assertFalse(report.ok)
            rules = {i.rule for i in report.issues}
            self.assertIn("BPR-TRUST-001", rules)

    def test_unmasked_real_phi_heuristics_flagged_and_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fhir_dir = root / "fhir"
            fhir_dir.mkdir()
            real_email = "real.patient" + "@" + "gmail.com"
            real_phone = "+966" + "558765432"
            patient = {
                "resource" + "Type": "Patient",
                "id": "pat-phi",
                "telecom": [
                    {"system": "email", "value": real_email},
                    {"system": "phone", "value": real_phone},
                ],
            }
            (fhir_dir / "leak.json").write_text(json.dumps(patient), encoding="utf-8")
            report = bpr_verify.run_verification(
                root=root, trust_dir=None, fhir_paths=["fhir"], require_trust=False, require_fhir=True
            )
            self.assertFalse(report.ok)
            rules = {i.rule for i in report.issues}
            self.assertIn("BPR-PHI-002", rules)
            self.assertIn("BPR-PHI-003", rules)
            # Ensure raw PHI never appears in formatted issue messages
            combined_messages = " ".join(i.message for i in report.issues)
            self.assertNotIn(real_email, combined_messages)
            self.assertNotIn(real_phone, combined_messages)


class CliIntegrationTests(unittest.TestCase):
    def test_cli_writes_json_report_and_markdown_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            create_test_pki(root / "trust")
            json_out = root / "out" / "report.json"
            md_out = root / "out" / "summary.md"
            rc = bpr_verify.main(
                [
                    "--root", str(root),
                    "--trust-dir", "trust",
                    "--min-days", "30",
                    "--json-report", str(json_out),
                    "--markdown-summary", str(md_out),
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(payload["ok"])
            self.assertGreaterEqual(payload["certificates_checked"], 4)
            self.assertIn("PASS", md_out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
