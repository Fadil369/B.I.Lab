"""Unit tests for phi_scan. All identifiers are synthetic and generated at runtime.

Run: python -m unittest discover -s script/phi-scan -v
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import phi_scan as ps


def make_luhn(prefix9: str) -> str:
    """Append the Luhn check digit to a 9-digit synthetic prefix."""
    for d in "0123456789":
        if ps.luhn_valid(prefix9 + d):
            return prefix9 + d
    raise AssertionError("unreachable")


SYN_NID = make_luhn("108273645")   # synthetic citizen-shaped ID
SYN_IQAMA = make_luhn("239184756")  # synthetic resident-shaped ID
SYN_SSN = "-".join(["345", "67", "8912"])
SYN_IBAN = "SA" + "44" + "20000001234567891234"
SYN_IBAN_SPACED = " ".join(["SA44", "2000", "0001", "2345", "6789", "1234"])
SYN_SCFHS = "-".join(["18", "R", "M", "0012345"])


class ScanCase(unittest.TestCase):
    def scan(self, files: dict, config: dict | None = None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    p.write_bytes(content)
                else:
                    p.write_text(content, encoding="utf-8")
            if config is not None:
                (root / ".phi-scan.json").write_text(json.dumps(config))
            cfg = ps.Config.load(root / ".phi-scan.json")
            findings, _ = ps.scan(root, cfg)
            sarif = ps.to_sarif(findings, root)
            return findings, sarif

    def ids(self, findings, include_suppressed=False):
        return sorted(f.rule.id for f in findings if include_suppressed or not f.suppressed)


class TestHelpers(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(ps.luhn_valid("79927398713"))
        self.assertFalse(ps.luhn_valid("79927398710"))
        self.assertTrue(ps.luhn_valid(SYN_NID))

    def test_mask_never_reveals_middle(self):
        self.assertEqual(ps.mask(SYN_NID), SYN_NID[:2] + "******" + SYN_NID[-2:])
        self.assertEqual(ps.mask("abc"), "***")


class TestDetectors(ScanCase):
    def test_national_id_with_keyword_is_high(self):
        f, _ = self.scan({"a.py": f'national_id = "{SYN_NID}"\n'})
        self.assertEqual(self.ids(f), ["PHI001"])
        self.assertEqual(f[0].severity, "high")

    def test_iqama_arabic_keyword(self):
        f, _ = self.scan({"a.md": f"رقم الإقامة: {SYN_IQAMA}\n"})
        self.assertEqual(self.ids(f), ["PHI001"])

    def test_epoch_timestamp_ignored(self):
        f, _ = self.scan({"a.js": f"const createdAt = {SYN_NID};\n"})
        self.assertEqual(self.ids(f), [])

    def test_bare_id_shaped_number_is_low(self):
        f, _ = self.scan({"a.txt": f"ref {SYN_NID}\n"})
        self.assertEqual(self.ids(f), ["PHI002"])
        self.assertEqual(f[0].severity, "low")

    def test_luhn_invalid_not_flagged(self):
        bad = SYN_NID[:-1] + str((int(SYN_NID[-1]) + 1) % 10)
        f, _ = self.scan({"a.py": f'national_id = "{bad}"\n'})
        self.assertEqual(self.ids(f), [])

    def test_ssn_and_known_examples(self):
        f, _ = self.scan({"a.txt": f"ssn {SYN_SSN}\nexample 123-45-6789\nreserved 987-65-4321\n"})
        self.assertEqual(self.ids(f), ["PHI003"])

    def test_mobile_bumped_near_patient(self):
        f, _ = self.scan({"a.py": "patient_phone = '0551234987'\nplaceholder = '0500000000'\n"})
        self.assertEqual(self.ids(f), ["PHI004"])
        self.assertEqual(f[0].severity, "medium")

    def test_email_safe_domains(self):
        f, _ = self.scan({"a.txt": "a@example.com b@users.noreply.github.com c@clinic-mail.sa\n"})
        self.assertEqual(self.ids(f), ["PHI005"])
        self.assertEqual(f[0].severity, "low")

    def test_mrn_literal_vs_code(self):
        f, _ = self.scan({"a.py": 'mrn = "MR204918"\npatient_id = request.args["id"]\n'})
        self.assertEqual(self.ids(f), ["PHI006"])

    def test_dob_gregorian_and_hijri(self):
        f, _ = self.scan({"a.json": '{"dob": "1987-03-14"}\n{"birthDate": "1407-07-12"}\n'})
        self.assertEqual(self.ids(f), ["PHI007", "PHI007"])

    def test_log_statement(self):
        f, _ = self.scan({"a.ts": "console.log('loaded', patient.nationalId);\n"
                                  "logger.info('patient_count=%d', n)\n"})
        self.assertEqual(self.ids(f), ["PHI008"])

    def test_saudi_iban_and_placeholder(self):
        placeholder = "SA" + ("0" * 22)
        f, sarif = self.scan({
            "billing.kt": (
                f'val iban = "{SYN_IBAN}"\n'
                f'val formatted = "{SYN_IBAN_SPACED}"\n'
                f'val safePlaceholder = "{placeholder}"\n'
            )
        })
        self.assertEqual(self.ids(f), ["PHI011", "PHI011"])
        self.assertTrue(all(item.severity == "high" for item in f))
        blob = json.dumps(sarif)
        self.assertNotIn(SYN_IBAN, blob)
        self.assertNotIn(SYN_IBAN_SPACED, blob)

    def test_kotlin_android_log_calls_and_scfhs_nphies_leaks(self):
        kotlin_src = "\n".join([
            'Log.d(TAG, "patient mrn=$mrn")',
            'Log.i(TAG, "clinician scfhsLicense=$scfhsLicense")',
            f'Log.w(TAG, "expired registration {SYN_SCFHS}")',
            'Log.e(TAG, "lookup failed for nphiesMemberId=$member")',
            'Log.v(TAG, "iban=$accountIban")',
            'Log.wtf(TAG, "corrupt payload nphies.sa/identifier/iqama/$id")',
            'Timber.d("sync patient=$id")',
            'Timber.i("scfhs_number=%s", scfhsNo)',
            'Timber.w("nphiesClaimId=%s", claimId)',
            'Timber.e("contact email=%s", userEmail)',
            'Timber.tag("BPR").d("clinician.scfhs=%s", lic)',
            'Log.e(',
            '    TAG,',
            '    "multiline nphiesIdentifier=$ref"',
            ')',
            'Timber.i("SCFHS trust store initialized")',
            'Log.i(TAG, "NPHIES client ready")',
        ]) + "\n"
        f, _ = self.scan({"BprLogger.kt": kotlin_src})
        phi008 = [item for item in f if item.rule.id == "PHI008"]
        self.assertEqual(len(phi008), 12)

    def test_log_phi008_avoids_prose_and_config_false_positives(self):
        kotlin_src = "\n".join([
            'Log.i(TAG, "Sync complete. NPHIES client ready")',
            'Log.i(TAG, "SCFHS: initialized")',
            'Log.d(TAG, "base " + config.nphiesBaseUrl)',
            'Log.d(TAG, "run 20-11-27-2026 done")',
        ]) + "\n"
        f, _ = self.scan({"Safe.kt": kotlin_src})
        self.assertEqual([x for x in f if x.rule.id == "PHI008"], [])

    def test_log_phi008_still_flags_assignments_and_member_access(self):
        kotlin_src = "\n".join([
            'Log.i(TAG, "scfhs: 1234567")',
            'Log.i(TAG, "scfhs=$value")',
            'Log.d(TAG, "who " + clinician.scfhs)',
        ]) + "\n"
        f, _ = self.scan({"Leaky.kt": kotlin_src})
        self.assertEqual(len([x for x in f if x.rule.id == "PHI008"]), 3)

    def test_fhir_patient_outside_synthetic(self):
        res = json.dumps({"resourceType": "Patient", "birthDate": "1990-01-01"})
        f, _ = self.scan({"fixtures/p.json": res, "fixtures/synthetic/p.json": res})
        rule_paths = [(x.rule.id, x.path) for x in f if x.rule.id == "PHI009"]
        self.assertEqual(rule_paths, [("PHI009", "fixtures/p.json")])

    def test_hl7_and_dicom(self):
        msg = "MSH|^~\\&|LAB|HOSP|||202401010000||ORU^R01|1|P|2.5\rPID|1||X^^^HOSP\n"
        f, _ = self.scan({"m.txt": msg.replace("\r", "\n"), "img.dcm": b"\x00DICM"})
        self.assertEqual(self.ids(f), ["PHI010", "PHI010"])


class TestSuppressionAndOutput(ScanCase):
    def test_inline_ignore_same_and_previous_line(self):
        f, sarif = self.scan({"a.py": f'national_id = "{SYN_NID}"  # phi-scan:ignore synthetic\n'
                                      f"# phi-scan:ignore test vector\nssn = '{SYN_SSN}'\n"})
        self.assertEqual(self.ids(f), [])
        self.assertEqual(len(self.ids(f, include_suppressed=True)), 2)
        results = sarif["runs"][0]["results"]
        self.assertTrue(all("suppressions" in r for r in results))

    def test_config_allow_and_exclude(self):
        f, _ = self.scan(
            {"a.py": f"ssn = '{SYN_SSN}'\n", "seed/b.py": f"national_id={SYN_NID}\n"},
            config={"allow_values": [SYN_SSN], "exclude_paths": ["seed/**"]},
        )
        self.assertEqual(self.ids(f), [])

    def test_bad_config_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ".phi-scan.json"
            p.write_text(json.dumps({"exclude": ["x"]}))
            with self.assertRaises(ValueError):
                ps.Config.load(p)

    def test_sarif_never_contains_raw_value(self):
        _, sarif = self.scan({"a.py": f'national_id = "{SYN_NID}"\nssn="{SYN_SSN}"\n'})
        blob = json.dumps(sarif)
        self.assertNotIn(SYN_NID, blob)
        self.assertNotIn(SYN_SSN, blob)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text(f'national_id = "{SYN_NID}"\n')
            self.assertEqual(ps.main(["--root", tmp, "--fail-on", "high"]), 1)
            self.assertEqual(ps.main(["--root", tmp, "--fail-on", "none"]), 0)
            self.assertEqual(ps.main(["--root", str(Path(tmp, "missing"))]), 2)


if __name__ == "__main__":
    unittest.main()
