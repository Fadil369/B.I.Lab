#!/usr/bin/env python3
"""BrainSAIT Provider Registry (BPR) X.509 PKI Trust & Synthetic FHIR R4 / NPHIES Validator.

Validates two governance surfaces using only the Python 3.10+ standard library and the
``openssl`` CLI:

1. X.509 PKI Trust Directory (e.g. ``trust/``):
   - Parses PEM (``*.pem``) and DER (``*.cer``, ``*.der``) certificates via ``openssl x509``.
   - Verifies cryptographic chain issuance: ``openssl verify -CAfile bpr-root.pem bpr-issuing.pem``
     and ``bpr-chain.pem`` certificates.
   - Verifies ``bpr-root.cer`` SHA-256 fingerprint matches ``bpr-root.pem`` when both exist, and
     validates ``fingerprints.txt`` entries when present.
   - Enforces ``notBefore <= now`` and ``days_until_expiry >= --min-days`` (default 30).

2. Synthetic FHIR R4 / NPHIES Bundles & BPR Schemas:
   - Validates FHIR R4 ``resourceType`` membership, ``Bundle`` entries, and ``CapabilityStatement``
     FHIR R4 version (``4.0.x``).
   - Validates NPHIES Saudi National ID (``1\\d{9}``) and Iqama (``2\\d{9}``) format + Luhn mod-10
     checksums across FHIR ``identifier`` arrays and BPR enrollment payloads.
   - Enforces neutral ``NOT_ASSESSED`` / ``not_assessed`` trust enum governance (unassessed licences
     and credentials must use neutral ``NOT_ASSESSED`` semantics, never negative labels like
     ``UNTRUSTED``, ``FAKE``, ``INVALID``, or ``FAILED``).
   - Flags unmasked real-looking PHI heuristics (non-synthetic emails/phones on Patient records,
     US SSNs, or non-synthetic Patient exports) with masked reporting so raw values never leak to CI.

Exit codes:
    0  all configured checks passed
    1  one or more verification errors found
    2  CLI usage or configuration error
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

__version__ = "1.0.0"

PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\r\n]+\s*-----END CERTIFICATE-----",
    re.MULTILINE,
)

FINGERPRINT_LINE_RE = re.compile(
    r"^(?P<label>.+?)\s+SHA-256:\s*(?P<hex>(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})\s*$"
)

VALID_FHIR_R4_RESOURCES = frozenset({
    "Account", "ActivityDefinition", "AllergyIntolerance", "Appointment", "AppointmentResponse",
    "AuditEvent", "Basic", "Binary", "BodyStructure", "Bundle", "CapabilityStatement", "CarePlan",
    "CareTeam", "ChargeItem", "Claim", "ClaimResponse", "ClinicalImpression", "CodeSystem",
    "Communication", "CommunicationRequest", "Composition", "ConceptMap", "Condition", "Consent",
    "Coverage", "CoverageEligibilityRequest", "CoverageEligibilityResponse", "DetectedIssue",
    "Device", "DiagnosticReport", "DocumentManifest", "DocumentReference", "Encounter", "Endpoint",
    "EpisodeOfCare", "ExplanationOfBenefit", "FamilyMemberHistory", "Flag", "Goal",
    "HealthcareService", "ImagingStudy", "Immunization", "ImplementationGuide", "InsurancePlan",
    "Invoice", "Library", "List", "Location", "Measure", "MeasureReport", "Media", "Medication",
    "MedicationAdministration", "MedicationDispense", "MedicationRequest", "MedicationStatement",
    "MessageDefinition", "MessageHeader", "NamingSystem", "NutritionOrder", "Observation",
    "OperationDefinition", "OperationOutcome", "Organization", "OrganizationAffiliation",
    "Parameters", "Patient", "PaymentNotice", "PaymentReconciliation", "Person", "PlanDefinition",
    "Practitioner", "PractitionerRole", "Procedure", "Provenance", "Questionnaire",
    "QuestionnaireResponse", "RelatedPerson", "RequestGroup", "RiskAssessment", "Schedule",
    "SearchParameter", "ServiceRequest", "Slot", "Specimen", "StructureDefinition", "Subscription",
    "Substance", "SupplyDelivery", "SupplyRequest", "Task", "ValueSet", "VisionPrescription",
})

# Additional valid FHIR R4 resource types (the base list above is not exhaustive).
VALID_FHIR_R4_RESOURCES = VALID_FHIR_R4_RESOURCES | frozenset({
    "Group", "DeviceRequest", "DeviceMetric", "DeviceUseStatement", "Contract",
    "EnrollmentRequest", "EnrollmentResponse", "ImmunizationRecommendation",
    "ImmunizationEvaluation", "ResearchStudy", "ResearchSubject", "MedicationKnowledge",
    "TestReport", "StructureMap",
})

VALID_BUNDLE_TYPES = frozenset({
    "document", "message", "transaction", "transaction-response",
    "batch", "batch-response", "history", "searchset", "collection",
})

NPHIES_NATIONAL_ID_SYSTEMS = frozenset({
    "http://nphies.sa/identifier/nationalid",
    "https://nphies.sa/identifier/nationalid",
})

NPHIES_IQAMA_SYSTEMS = frozenset({
    "http://nphies.sa/identifier/iqama",
    "https://nphies.sa/identifier/iqama",
})

ALLOWED_LICENCE_TRUST_STATUS = frozenset({
    "VERIFIED", "NOT_ASSESSED", "EXPIRED", "REVOKED",
})

ALLOWED_WEB_TRUST_VALUES = {
    "identity": frozenset({"confirmed", "verified", "linked", "not_linked", "not_assessed", "none"}),
    "signature": frozenset({"current", "valid", "verified", "expired", "revoked", "none", "not_assessed"}),
    "membership": frozenset({"active", "expired", "suspended", "none", "not_assessed"}),
    "licence": frozenset({"verified", "not_assessed", "expired", "revoked"}),
    "qualifications": frozenset({"verified", "partial", "not_assessed", "expired", "revoked"}),
    "privileges": frozenset({"recorded", "verified", "active", "none", "not_assessed"}),
}

ALLOWED_WEB_VERIFICATION_VALUES = frozenset({
    "verified", "current", "confirmed", "not_assessed", "none", "expired", "revoked",
})

# Metadata fields inside a `verification` object (timestamps, actors, links) are not status values.
NON_STATUS_VERIFICATION_SUFFIXES = ("at", "date", "time", "timestamp", "by", "source", "note", "notes", "url", "id")

FORBIDDEN_NON_NEUTRAL_TRUST_TERMS = frozenset({
    "untrusted", "unverified", "fake", "fraud", "fraudulent",
    "blacklisted", "suspicious", "failed", "invalid", "unlicensed", "rejected",
})

SAFE_SYNTHETIC_EMAIL_DOMAINS = re.compile(
    r"(?i)@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|test|invalid|localhost|"
    r"brainsait\.(?:de|com|io|org)|chatgpt\.site|noreply\.github\.com)$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
SA_MOBILE_RE = re.compile(r"^(?:\+966|00966|966)?0?5\d{8}$")
SSN_RE = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
KNOWN_TEST_SSNS = frozenset({"078-05-1120", "123-45-6789", "219-09-9999", "457-55-5462"})


@dataclass
class CertReport:
    path: str
    index: int
    encoding: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_remaining: int
    sha256_fingerprint: str
    chain_verified: Optional[bool] = None


@dataclass
class Issue:
    category: str
    severity: str
    path: str
    rule: str
    message: str


@dataclass
class VerificationReport:
    ok: bool
    timestamp: str
    min_days: int
    certificates_checked: int = 0
    json_files_checked: int = 0
    fhir_resources_checked: int = 0
    bpr_records_checked: int = 0
    certificates: list[CertReport] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    def add_error(self, category: str, path: str, rule: str, message: str) -> None:
        self.issues.append(Issue(category=category, severity="error", path=path, rule=rule, message=message))
        self.ok = False

    def add_warning(self, category: str, path: str, rule: str, message: str) -> None:
        self.issues.append(Issue(category=category, severity="warning", path=path, rule=rule, message=message))


def mask_value(raw: str) -> str:
    """Mask sensitive values so console output and JSON reports never expose full PHI."""
    val = str(raw).strip()
    if len(val) <= 4:
        return "*" * len(val)
    return val[:2] + "*" * (len(val) - 4) + val[-2:]


def saudi_id_luhn_valid(value: str) -> bool:
    """Return True if a 10-digit Saudi National ID / Iqama passes the Luhn mod-10 check."""
    if len(value) != 10 or not value.isdigit() or value[0] not in ("1", "2"):
        return False
    total = 0
    for idx, ch in enumerate(value):
        digit = int(ch)
        if idx % 2 == 0:
            doubled = digit * 2
            total += doubled // 10 + doubled % 10
        else:
            total += digit
    return total % 10 == 0


def is_synthetic_phone(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return True
    tail = digits[-8:] if len(digits) >= 8 else digits
    if len(set(tail)) <= 2:
        return True
    if digits.endswith(("12345678", "00000000", "00000001", "99999999")):
        return True
    return False


def parse_openssl_time(value: str) -> dt.datetime:
    """Parse OpenSSL ASN1_TIME output (e.g. 'Nov 10 22:55:45 2031 GMT') into aware UTC datetime."""
    cleaned = " ".join(value.strip().split())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = dt.datetime.strptime(cleaned, fmt)
            return parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    parsed_email = email.utils.parsedate_to_datetime(cleaned)
    if parsed_email.tzinfo is None:
        return parsed_email.replace(tzinfo=dt.timezone.utc)
    return parsed_email.astimezone(dt.timezone.utc)


def _run_openssl(args: list[str], stdin_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["openssl", *args],
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def inspect_cert_bytes(
    cert_bytes: bytes,
    encoding: str,
    rel_path: str,
    index: int,
    now: dt.datetime,
    min_days: int,
    report: VerificationReport,
) -> Optional[CertReport]:
    inform = ["-inform", "DER"] if encoding == "DER" else ["-inform", "PEM"]
    proc = _run_openssl(
        ["x509", *inform, "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-fingerprint", "-sha256"],
        stdin_bytes=cert_bytes,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        detail = err[-1] if err else "openssl x509 failed"
        report.add_error("pki", rel_path, "BPR-PKI-001", f"Invalid {encoding} certificate (index {index}): {detail}")
        return None

    fields: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip().lower()] = v.strip()

    subject = fields.get("subject", "")
    issuer = fields.get("issuer", "")
    not_before_raw = fields.get("notbefore", "")
    not_after_raw = fields.get("notafter", "")
    fp = next((v for k, v in fields.items() if "fingerprint" in k), "").upper()

    try:
        not_before = parse_openssl_time(not_before_raw)
        not_after = parse_openssl_time(not_after_raw)
    except Exception as exc:
        report.add_error("pki", rel_path, "BPR-PKI-002", f"Unparseable certificate validity dates: {exc}")
        return None

    days_remaining = int((not_after - now).total_seconds() // 86400)
    if now < not_before:
        report.add_error(
            "pki",
            rel_path,
            "BPR-PKI-003",
            f"Certificate (index {index}) is not valid until {not_before.isoformat()}",
        )
    if days_remaining < min_days:
        report.add_error(
            "pki",
            rel_path,
            "BPR-PKI-004",
            f"Certificate (index {index}, subject '{subject}') expires in {days_remaining} days "
            f"(minimum required: {min_days} days; notAfter={not_after.isoformat()})",
        )

    cert_info = CertReport(
        path=rel_path,
        index=index,
        encoding=encoding,
        subject=subject,
        issuer=issuer,
        not_before=not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        days_remaining=days_remaining,
        sha256_fingerprint=fp,
    )
    report.certificates.append(cert_info)
    report.certificates_checked += 1
    return cert_info


def verify_pem_chain(ca_pem: Path, leaf_pem_bytes: bytes) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        tmp.write(leaf_pem_bytes)
        tmp_path = Path(tmp.name)
    try:
        proc = _run_openssl(["verify", "-CAfile", str(ca_pem), str(tmp_path)])
        output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace").strip()
        return proc.returncode == 0, output
    finally:
        tmp_path.unlink(missing_ok=True)


def verify_trust_directory(
    root: Path,
    trust_dir: Path,
    min_days: int,
    now: dt.datetime,
    report: VerificationReport,
) -> None:
    rel_trust = os.path.relpath(trust_dir, root).replace(os.sep, "/")
    if not trust_dir.is_dir():
        report.add_error("pki", rel_trust, "BPR-PKI-000", f"Trust directory does not exist: {rel_trust}")
        return

    root_pem = trust_dir / "bpr-root.pem"
    issuing_pem = trust_dir / "bpr-issuing.pem"
    chain_pem = trust_dir / "bpr-chain.pem"

    if not root_pem.is_file():
        report.add_error("pki", f"{rel_trust}/bpr-root.pem", "BPR-PKI-005", "Missing required Root CA bpr-root.pem")
    if not issuing_pem.is_file():
        report.add_error(
            "pki", f"{rel_trust}/bpr-issuing.pem", "BPR-PKI-006", "Missing required Issuing CA bpr-issuing.pem"
        )

    pem_files = sorted(trust_dir.glob("*.pem"))
    der_files = sorted([*trust_dir.glob("*.cer"), *trust_dir.glob("*.der")])
    if not pem_files and not der_files:
        report.add_error("pki", rel_trust, "BPR-PKI-007", "No .pem, .cer, or .der certificates found in trust dir")
        return

    cert_by_name: dict[str, list[CertReport]] = {}

    for pem_file in pem_files:
        rel = os.path.relpath(pem_file, root).replace(os.sep, "/")
        text = pem_file.read_text(encoding="utf-8", errors="replace")
        blocks = PEM_CERT_RE.findall(text)
        if not blocks:
            report.add_error("pki", rel, "BPR-PKI-001", "No PEM CERTIFICATE block found")
            continue
        parsed_list: list[CertReport] = []
        for idx, block in enumerate(blocks):
            info = inspect_cert_bytes(block.encode("utf-8"), "PEM", rel, idx, now, min_days, report)
            if info is not None:
                if root_pem.is_file():
                    ok, detail = verify_pem_chain(root_pem, block.encode("utf-8"))
                    info.chain_verified = ok
                    if not ok:
                        report.add_error(
                            "pki",
                            rel,
                            "BPR-PKI-008",
                            f"Chain verification against bpr-root.pem failed (cert {idx}): {detail}",
                        )
                parsed_list.append(info)
        cert_by_name[pem_file.name] = parsed_list

    for der_file in der_files:
        rel = os.path.relpath(der_file, root).replace(os.sep, "/")
        raw = der_file.read_bytes()
        encoding = "PEM" if b"-----BEGIN CERTIFICATE-----" in raw else "DER"
        info = inspect_cert_bytes(raw, encoding, rel, 0, now, min_days, report)
        if info is not None:
            cert_by_name[der_file.name] = [info]

    # Root CA self-signed invariant
    root_infos = cert_by_name.get("bpr-root.pem", [])
    if root_infos:
        root_info = root_infos[0]
        if root_info.subject != root_info.issuer:
            report.add_error(
                "pki",
                root_info.path,
                "BPR-PKI-009",
                f"Root CA must be self-issued, got subject='{root_info.subject}' vs issuer='{root_info.issuer}'",
            )
        # Ensure bpr-root.cer matches bpr-root.pem if present
        cer_infos = cert_by_name.get("bpr-root.cer", [])
        if cer_infos and cer_infos[0].sha256_fingerprint != root_info.sha256_fingerprint:
            report.add_error(
                "pki",
                cer_infos[0].path,
                "BPR-PKI-010",
                "bpr-root.cer SHA-256 fingerprint does not match bpr-root.pem",
            )

    # Chain bundle invariant (issuing + root when bpr-chain.pem exists)
    if chain_pem.is_file():
        chain_infos = cert_by_name.get("bpr-chain.pem", [])
        if len(chain_infos) < 2:
            report.add_error(
                "pki",
                f"{rel_trust}/bpr-chain.pem",
                "BPR-PKI-011",
                f"Expected at least 2 certificates in bpr-chain.pem (issuing + root), found {len(chain_infos)}",
            )

    # Explicit openssl verify -CAfile bpr-root.pem bpr-issuing.pem check
    if root_pem.is_file() and issuing_pem.is_file():
        proc = _run_openssl(["verify", "-CAfile", str(root_pem), str(issuing_pem)])
        if proc.returncode != 0:
            detail = (proc.stdout + proc.stderr).decode("utf-8", errors="replace").strip()
            report.add_error(
                "pki",
                f"{rel_trust}/bpr-issuing.pem",
                "BPR-PKI-008",
                f"openssl verify -CAfile bpr-root.pem bpr-issuing.pem failed: {detail}",
            )

    # Optional fingerprints.txt consistency check
    fp_file = trust_dir / "fingerprints.txt"
    if fp_file.is_file():
        rel_fp = os.path.relpath(fp_file, root).replace(os.sep, "/")
        known_fps = {info.sha256_fingerprint for infos in cert_by_name.values() for info in infos}
        for line_no, line in enumerate(fp_file.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            m = FINGERPRINT_LINE_RE.match(stripped)
            if not m:
                report.add_error(
                    "pki",
                    rel_fp,
                    "BPR-PKI-012",
                    f"Malformed SHA-256 entry on line {line_no} of fingerprints.txt",
                )
                continue
            expected_fp = m.group("hex").upper()
            if expected_fp not in known_fps:
                report.add_error(
                    "pki",
                    rel_fp,
                    "BPR-PKI-013",
                    f"Fingerprint for '{m.group('label').strip()}' on line {line_no} matches no certificate in {rel_trust}",
                )


def _check_saudi_identifier(
    value: Any,
    expected_prefix: Optional[str],
    rel_path: str,
    context_label: str,
    report: VerificationReport,
) -> None:
    if not isinstance(value, str):
        report.add_error("fhir", rel_path, "BPR-NPHIES-001", f"{context_label} must be a string")
        return
    val = value.strip()
    # Allow already-masked display strings like 1******789
    if "*" in val:
        return
    if len(val) != 10 or not val.isdigit() or val[0] not in ("1", "2"):
        report.add_error(
            "fhir",
            rel_path,
            "BPR-NPHIES-001",
            f"{context_label} '{mask_value(val)}' must be a 10-digit Saudi National ID (1...) or Iqama (2...)",
        )
        return
    if expected_prefix and val[0] != expected_prefix:
        kind_name = "Saudi National ID (1...)" if expected_prefix == "1" else "Saudi Iqama (2...)"
        report.add_error(
            "fhir",
            rel_path,
            "BPR-NPHIES-002",
            f"{context_label} '{mask_value(val)}' does not match expected prefix for {kind_name}",
        )
        return
    if not saudi_id_luhn_valid(val):
        report.add_error(
            "fhir",
            rel_path,
            "BPR-NPHIES-003",
            f"{context_label} '{mask_value(val)}' failed Luhn mod-10 checksum verification",
        )


def _scan_string_for_phi(
    val: str, key: str, phone_context: bool, patient_scope: bool, rel_path: str, report: VerificationReport
) -> None:
    stripped = val.strip()
    for ssn_match in SSN_RE.finditer(stripped):
        ssn = ssn_match.group(0)
        if ssn not in KNOWN_TEST_SSNS and not ssn.startswith("987-65-432"):
            report.add_error(
                "phi",
                rel_path,
                "BPR-PHI-001",
                f"Possible unmasked US SSN '{mask_value(ssn)}' in field '{key}'",
            )
    if patient_scope and EMAIL_RE.match(stripped):
        if not SAFE_SYNTHETIC_EMAIL_DOMAINS.search(stripped):
            report.add_error(
                "phi",
                rel_path,
                "BPR-PHI-002",
                f"Unmasked non-synthetic email '{mask_value(stripped)}' on patient payload",
            )
    compact_phone = re.sub(r"[\s()-]", "", stripped)
    if (patient_scope or phone_context) and SA_MOBILE_RE.match(compact_phone):
        if not is_synthetic_phone(compact_phone):
            report.add_error(
                "phi",
                rel_path,
                "BPR-PHI-003",
                f"Unmasked non-synthetic Saudi mobile '{mask_value(stripped)}' in field '{key}'",
            )


def _check_unmasked_phi_in_strings(
    obj: Any, rel_path: str, in_patient_scope: bool, report: VerificationReport,
    parent_key: str = "", parent_phone_context: bool = False,
) -> None:
    if isinstance(obj, dict):
        next_patient_scope = in_patient_scope or (
            obj.get("resourceType") == "Patient" or "patient_name_en" in obj
        )
        # FHIR ContactPoint: {"system": "phone", "value": "..."}; a bare "value" key elsewhere
        # (identifiers, licence numbers) is not a phone number.
        contact_point_is_phone = str(obj.get("system", "")).lower() in {"phone", "sms"}
        for key, val in obj.items():
            key_lower = str(key).lower()
            phone_context = key_lower in {"phone", "mobile", "telecom"} or (
                key_lower == "value" and contact_point_is_phone
            )
            if isinstance(val, str):
                _scan_string_for_phi(val, str(key), phone_context, next_patient_scope, rel_path, report)
            else:
                _check_unmasked_phi_in_strings(
                    val, rel_path, next_patient_scope, report, parent_key=str(key), parent_phone_context=phone_context
                )
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, str):
                _scan_string_for_phi(item, parent_key, parent_phone_context, in_patient_scope, rel_path, report)
            else:
                _check_unmasked_phi_in_strings(
                    item, rel_path, in_patient_scope, report,
                    parent_key=parent_key, parent_phone_context=parent_phone_context,
                )


def validate_fhir_resource(obj: dict[str, Any], rel_path: str, report: VerificationReport) -> None:
    res_type = obj.get("resourceType")
    if not isinstance(res_type, str) or not res_type.strip():
        report.add_error("fhir", rel_path, "BPR-FHIR-001", "FHIR resource missing non-empty string 'resourceType'")
        return
    if res_type not in VALID_FHIR_R4_RESOURCES:
        report.add_error("fhir", rel_path, "BPR-FHIR-002", f"Unsupported or invalid FHIR R4 resourceType '{res_type}'")
        return

    report.fhir_resources_checked += 1

    if res_type == "CapabilityStatement":
        fhir_ver = obj.get("fhirVersion")
        if fhir_ver is not None and (not isinstance(fhir_ver, str) or not fhir_ver.startswith("4.0")):
            report.add_error(
                "fhir",
                rel_path,
                "BPR-FHIR-003",
                f"CapabilityStatement.fhirVersion expected 4.0.x (FHIR R4), got '{fhir_ver}'",
            )

    if res_type == "Bundle":
        btype = obj.get("type")
        if not isinstance(btype, str) or btype not in VALID_BUNDLE_TYPES:
            report.add_error(
                "fhir",
                rel_path,
                "BPR-FHIR-004",
                f"Bundle.type must be one of {sorted(VALID_BUNDLE_TYPES)}, got '{btype}'",
            )
        entries = obj.get("entry", [])
        if not isinstance(entries, list):
            report.add_error("fhir", rel_path, "BPR-FHIR-005", "Bundle.entry must be a JSON array")
        else:
            for idx, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    report.add_error("fhir", rel_path, "BPR-FHIR-005", f"Bundle.entry[{idx}] must be an object")
                    continue
                nested = entry.get("resource")
                if nested is not None:
                    if not isinstance(nested, dict):
                        report.add_error(
                            "fhir", rel_path, "BPR-FHIR-005", f"Bundle.entry[{idx}].resource must be an object"
                        )
                    else:
                        validate_fhir_resource(nested, f"{rel_path}#entry[{idx}]", report)

    identifiers = obj.get("identifier")
    if identifiers is not None:
        if not isinstance(identifiers, list):
            report.add_error("fhir", rel_path, "BPR-FHIR-006", f"{res_type}.identifier must be a JSON array")
        else:
            for idx, ident in enumerate(identifiers):
                if not isinstance(ident, dict):
                    continue
                system = str(ident.get("system", "")).strip()
                value = ident.get("value")
                if system in NPHIES_NATIONAL_ID_SYSTEMS:
                    _check_saudi_identifier(
                        value, "1", rel_path, f"{res_type}.identifier[{idx}] (NPHIES National ID)", report
                    )
                elif system in NPHIES_IQAMA_SYSTEMS:
                    _check_saudi_identifier(
                        value, "2", rel_path, f"{res_type}.identifier[{idx}] (NPHIES Iqama)", report
                    )


def _check_neutral_trust_term(value: Any, field_label: str, rel_path: str, report: VerificationReport) -> None:
    if isinstance(value, str):
        norm = value.strip().lower()
        if norm in FORBIDDEN_NON_NEUTRAL_TRUST_TERMS:
            report.add_error(
                "bpr",
                rel_path,
                "BPR-TRUST-001",
                f"Field '{field_label}' uses non-neutral negative status '{value}'; "
                f"unassessed records must use neutral 'NOT_ASSESSED' / 'not_assessed'",
            )


def validate_bpr_provider_record(obj: dict[str, Any], rel_path: str, report: VerificationReport) -> None:
    spid = obj.get("spid")
    if not isinstance(spid, str) or not spid.strip():
        report.add_error("bpr", rel_path, "BPR-SCHEMA-001", "BPR provider record missing non-empty 'spid'")
        return

    report.bpr_records_checked += 1

    # Android BprJsonCodec schema: licence_status
    if "licence_status" in obj and obj["licence_status"] is not None:
        raw_status = str(obj["licence_status"]).strip()
        _check_neutral_trust_term(raw_status, "licence_status", rel_path, report)
        if raw_status.upper() not in ALLOWED_LICENCE_TRUST_STATUS:
            report.add_error(
                "bpr",
                rel_path,
                "BPR-TRUST-002",
                f"Invalid licence_status '{raw_status}' on {spid}; expected one of {sorted(ALLOWED_LICENCE_TRUST_STATUS)}",
            )

    # Web registry schema: trust object & verification object
    trust_obj = obj.get("trust")
    if isinstance(trust_obj, dict):
        for t_key, t_val in trust_obj.items():
            _check_neutral_trust_term(t_val, f"trust.{t_key}", rel_path, report)
            allowed = ALLOWED_WEB_TRUST_VALUES.get(t_key)
            if allowed is not None and (not isinstance(t_val, str) or t_val not in allowed):
                report.add_error(
                    "bpr",
                    rel_path,
                    "BPR-TRUST-003",
                    f"Invalid trust.{t_key}='{t_val}' on {spid}; expected one of {sorted(allowed)}",
                )

    ver_obj = obj.get("verification")
    if isinstance(ver_obj, dict):
        for v_key, v_val in ver_obj.items():
            _check_neutral_trust_term(v_val, f"verification.{v_key}", rel_path, report)
            if str(v_key).lower().endswith(NON_STATUS_VERIFICATION_SUFFIXES):
                continue
            if not isinstance(v_val, str) or v_val not in ALLOWED_WEB_VERIFICATION_VALUES:
                report.add_error(
                    "bpr",
                    rel_path,
                    "BPR-TRUST-004",
                    f"Invalid verification.{v_key}='{v_val}' on {spid}; "
                    f"expected one of {sorted(ALLOWED_WEB_VERIFICATION_VALUES)}",
                )


def validate_json_file(json_path: Path, root: Path, report: VerificationReport) -> None:
    rel = os.path.relpath(json_path, root).replace(os.sep, "/")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        report.add_error("json", rel, "BPR-JSON-001", f"Malformed JSON file: {exc}")
        return

    report.json_files_checked += 1
    _check_unmasked_phi_in_strings(data, rel, in_patient_scope=False, report=report)
    validate_json_document(data, rel, report)


def validate_json_document(data: Any, rel: str, report: VerificationReport) -> None:
    """Dispatch a parsed JSON value to the schema checks. Lists are validated item by item."""
    if isinstance(data, list):
        for idx, item in enumerate(data):
            if isinstance(item, (dict, list)):
                validate_json_document(item, f"{rel}[{idx}]", report)
        return

    if not isinstance(data, dict):
        return

    # 1. FHIR R4 resource or Bundle
    if "resourceType" in data:
        validate_fhir_resource(data, rel, report)
        return

    # 2. BOS Enrollment Draft (Android BprJsonCodec)
    if "patient_name_en" in data and "national_id" in data:
        report.bpr_records_checked += 1
        _check_saudi_identifier(data.get("national_id"), None, rel, "BosEnrollmentDraft.national_id", report)
        return

    # 3. Single BPR provider record (any object carrying an 'spid')
    if "spid" in data:
        validate_bpr_provider_record(data, rel, report)
        return

    # 4. BPR Verifiable Credential wrapper (vc/*.json)
    if isinstance(data.get("credential"), dict):
        subj = data["credential"].get("credentialSubject")
        if isinstance(subj, dict) and "spid" in subj:
            report.bpr_records_checked += 1
            ver_level = subj.get("verificationLevel")
            if ver_level is not None:
                _check_neutral_trust_term(ver_level, "credentialSubject.verificationLevel", rel, report)
                if str(ver_level).lower() not in {"not_assessed", "verified", "partial"}:
                    report.add_error(
                        "bpr",
                        rel,
                        "BPR-TRUST-005",
                        f"Unexpected credentialSubject.verificationLevel '{ver_level}'",
                    )

    # 5. Containers: any list-valued key (items[], providers[], entries, ...) whose elements are
    #    BPR providers or FHIR resources is validated, so records are not skipped by key name.
    for list_key, arr in data.items():
        if isinstance(arr, list):
            for idx, item in enumerate(arr):
                if isinstance(item, dict) and ("spid" in item or "resourceType" in item):
                    validate_json_document(item, f"{rel}#{list_key}[{idx}]", report)


def collect_json_files(root: Path, raw_paths: Iterable[str]) -> list[Path]:
    discovered: list[Path] = []
    seen: set[Path] = set()
    for p_str in raw_paths:
        if not p_str.strip():
            continue
        candidate = Path(p_str)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file() and candidate.suffix.lower() == ".json":
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(candidate)
        elif candidate.is_dir():
            for child in sorted(candidate.rglob("*.json")):
                if any(part in {"node_modules", ".git", "build", "dist"} for part in child.relative_to(candidate).parts):
                    continue
                resolved = child.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    discovered.append(child)
    return discovered


def render_markdown_summary(report: VerificationReport) -> str:
    verdict = "PASS" if report.ok else "FAIL"
    lines = [
        f"## BPR PKI & FHIR Governance Verification: **{verdict}**",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Status | **{verdict}** |",
        f"| Minimum expiry horizon | `{report.min_days}` days |",
        f"| X.509 certificates verified | `{report.certificates_checked}` |",
        f"| JSON files inspected | `{report.json_files_checked}` |",
        f"| FHIR R4 resources validated | `{report.fhir_resources_checked}` |",
        f"| BPR records validated | `{report.bpr_records_checked}` |",
        f"| Issues found | `{len(report.issues)}` |",
        "",
    ]
    if report.certificates:
        lines.extend([
            "### X.509 Trust Inventory",
            "",
            "| Certificate | Encoding | Subject | Not After (UTC) | Days Left | Chain OK |",
            "|---|---|---|---|---|---|",
        ])
        for cert in report.certificates:
            chain_cell = "n/a" if cert.chain_verified is None else ("yes" if cert.chain_verified else "NO")
            lines.append(
                f"| `{cert.path}` (#{cert.index}) | `{cert.encoding}` | `{cert.subject}` | "
                f"`{cert.not_after}` | `{cert.days_remaining}` | `{chain_cell}` |"
            )
        lines.append("")

    if report.issues:
        lines.extend([
            "### Findings",
            "",
            "| Severity | Rule | Path | Message |",
            "|---|---|---|---|",
        ])
        for issue in report.issues:
            safe_msg = issue.message.replace("|", "\\|")
            lines.append(f"| `{issue.severity}` | `{issue.rule}` | `{issue.path}` | {safe_msg} |")
        lines.append("")

    return "\n".join(lines)


def run_verification(
    root: Path,
    trust_dir: Optional[str] = "trust",
    fhir_paths: Optional[list[str]] = None,
    min_days: int = 30,
    require_trust: bool = True,
    require_fhir: bool = False,
    now: Optional[dt.datetime] = None,
) -> VerificationReport:
    effective_now = now or dt.datetime.now(dt.timezone.utc)
    report = VerificationReport(
        ok=True,
        timestamp=effective_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        min_days=min_days,
    )

    if trust_dir:
        t_path = Path(trust_dir) if Path(trust_dir).is_absolute() else (root / trust_dir)
        if t_path.exists() or require_trust:
            verify_trust_directory(root=root, trust_dir=t_path, min_days=min_days, now=effective_now, report=report)

    effective_fhir_paths: list[str] = []
    if fhir_paths:
        for item in fhir_paths:
            effective_fhir_paths.extend(tok for tok in re.split(r"[\s,]+", item.strip()) if tok)
    else:
        for default_rel in ("fhir", "public/assets/bpr-data"):
            if (root / default_rel).exists():
                effective_fhir_paths.append(default_rel)

    json_files = collect_json_files(root, effective_fhir_paths)
    if require_fhir and not json_files:
        report.add_error(
            "fhir",
            ",".join(effective_fhir_paths) or ".",
            "BPR-FHIR-000",
            "No FHIR/BPR JSON files found in configured paths",
        )

    for jf in json_files:
        validate_json_file(jf, root, report)

    if (require_trust or require_fhir) and report.certificates_checked == 0 and report.json_files_checked == 0 and report.ok:
        report.add_error(
            "config",
            ".",
            "BPR-CFG-001",
            "Neither X.509 certificates nor FHIR/BPR JSON files were found to verify",
        )

    return report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify BPR X.509 PKI trust chains and synthetic FHIR R4 / NPHIES / BPR JSON contracts."
    )
    parser.add_argument("--root", default=".", help="Repository root directory (default: .)")
    parser.add_argument(
        "--trust-dir",
        default="trust",
        help="Relative or absolute path to PKI trust directory (pass '' to skip PKI verification)",
    )
    parser.add_argument(
        "--fhir-paths",
        nargs="*",
        default=None,
        help="Space- or comma-separated files/directories of synthetic FHIR R4 / BPR JSON payloads",
    )
    parser.add_argument(
        "--min-days",
        type=int,
        default=30,
        help="Minimum days until X.509 certificate expiry (default: 30)",
    )
    parser.add_argument(
        "--require-trust",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail when --trust-dir is missing (default: true)",
    )
    parser.add_argument(
        "--require-fhir",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail when no FHIR/BPR JSON files are found (default: false)",
    )
    parser.add_argument("--json-report", default=None, help="Write full JSON verification report to this file")
    parser.add_argument("--markdown-summary", default=None, help="Append Markdown summary table to this file")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.min_days < 0:
        print("error: --min-days must be >= 0", file=sys.stderr)
        return 2

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: --root is not a directory: {root}", file=sys.stderr)
        return 2

    trust_arg = args.trust_dir.strip() if args.trust_dir is not None else ""
    report = run_verification(
        root=root,
        trust_dir=trust_arg or None,
        fhir_paths=args.fhir_paths,
        min_days=args.min_days,
        require_trust=bool(args.require_trust and trust_arg),
        require_fhir=args.require_fhir,
    )

    if args.json_report:
        out_path = Path(args.json_report)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")

    md = render_markdown_summary(report)
    if args.markdown_summary:
        md_path = Path(args.markdown_summary)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        with md_path.open("a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    print(md)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
