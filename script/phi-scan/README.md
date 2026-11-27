# phi-scan

Heuristic, dependency-free scanner that flags possible PHI (Saudi national ID / Iqama numbers,
Saudi IBANs, MRNs, dates of birth, phone numbers, emails, FHIR Patient fixtures, HL7/DICOM files,
and log calls — including Kotlin/Android `Log.*` and `Timber.*` — that mention patient, SCFHS
license or NPHIES identifier fields). Values are always masked in output.

```bash
python script/phi-scan/phi_scan.py --root . --fail-on medium --sarif phi-scan.sarif
python -m unittest discover -s script/phi-scan -v
```

It is a review aid, not a de-identification tool. Coverage, limits, rules and suppression
syntax are in [docs/healthcare-security-scan.md](../../docs/healthcare-security-scan.md).
