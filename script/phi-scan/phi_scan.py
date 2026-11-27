#!/usr/bin/env python3
"""Heuristic scanner that flags possible PHI (protected health information) in a repository.

BRAINSAIT: This is a *review aid*, not a de-identification tool. It looks for patterns that
often indicate real patient data or identifiers committed to source code, fixtures or logs,
and for logging statements that appear to write patient fields. It cannot prove a repository
is free of PHI. See docs/healthcare-security-scan.md for what it covers and what it misses.

Design rules:
  * Standard library only, so it runs on any runner with Python 3.9+.
  * Matched values are always masked in console output and SARIF, so the scan itself
    never copies PHI into CI logs or the code-scanning database.
  * Every finding can be suppressed inline (``phi-scan:ignore``) or via a config file,
    and suppressions are counted in the summary so reviewers can audit them.

Usage:
    python phi_scan.py --root . --sarif phi-scan.sarif --fail-on medium
    python phi_scan.py --root . --config .phi-scan.json --fail-on high

Exit codes:
    0  no unsuppressed finding at or above --fail-on
    1  at least one finding at or above --fail-on
    2  usage or configuration error

Examples (synthetic only):
    >>> luhn_valid("79927398713")
    True
    >>> mask("1234567890")
    '12******90'
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

__version__ = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {"none": 99, "low": 0, "medium": 1, "high": 2}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error"}
SARIF_SECURITY_SEVERITY = {"low": "3.0", "medium": "6.0", "high": "8.5"}

MAX_FILE_BYTES = 2 * 1024 * 1024
INLINE_IGNORE = "phi-scan:ignore"

DEFAULT_EXCLUDES = [
    ".git/**", "**/.git/**",
    "**/node_modules/**", "**/vendor/**", "**/.venv/**", "**/venv/**",
    "**/dist/**", "**/build/**", "**/.next/**", "**/coverage/**",
    "**/*.min.js", "**/*.min.css", "**/*.map",
    "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/poetry.lock",
    "**/Cargo.lock", "**/go.sum", "**/composer.lock", "**/Gemfile.lock",
    "**/*.sarif",
]

# File extensions that almost always hold clinical payloads rather than code.
CLINICAL_FILE_EXTENSIONS = {
    ".hl7": "HL7 v2 message file",
    ".dcm": "DICOM image",
    ".dicom": "DICOM image",
    ".nii": "NIfTI imaging volume",
    ".ccda": "C-CDA clinical document",
}

# Words that make a nearby number or contact detail much more likely to be about a patient.
# BILINGUAL: Arabic terms included (patient, identity, national ID, medical file, date of birth).
PATIENT_CONTEXT = re.compile(
    r"(?i)(patient|beneficiar|member[_ -]?id|subscriber|insured|mrn|medical[_ -]?record|"
    r"date[_ -]?of[_ -]?birth|\bdob\b|birth[_ -]?date|diagnos|nphies|claim|encounter|"
    r"national[_ -]?id|iqama|\bnid\b|مريض|المريض|هوية|الهوية|رقم\s*الملف|تاريخ\s*الميلاد)"
)

NATIONAL_ID_CONTEXT = re.compile(
    r"(?i)(national[_ -]?id|nationalid|\bnid\b|iqama|id[_ -]?number|identity|"
    r"resident[_ -]?id|هوية|الهوية|الإقامة|اقامة|رقم\s*السجل)"
)

# Names that look like time, not identity. Used to cut false positives on 10-digit numbers.
EPOCH_CONTEXT = re.compile(
    r"(?i)(time|epoch|timestamp|\bts\b|created|updated|expires?|\bexp\b|\biat\b|\bnbf\b|"
    r"date|millis|seconds|version|build|port|size|bytes|count|hash|nonce|seed)"
)

LOG_CALL = re.compile(
    r"(console\.(log|info|warn|error|debug|trace)|\blogger\.\w+|\blogging\.\w+|\blog\.\w+|"
    r"\bprint(ln|f)?\s*\(|\bputs\b|\bNSLog\b|\bos_log\b|\bLog\.[dievw]\b|\bfmt\.Print|"
    r"\bSystem\.out\.print|\bconsole\.table)"
)
LOG_SENSITIVE_FIELD = re.compile(
    r"(?i)(patient(?!s?_?count)|\bssn\b|national[_ ]?id|nationalid|iqama|\bmrn\b|\bdob\b|"
    r"date_?of_?birth|birth_?date|diagnos|beneficiary|member_?id|insurance_?(no|number|id)|"
    r"full_?name|first_?name|last_?name|phone|mobile|email|address)"
)

KNOWN_TEST_SSNS = {"078-05-1120", "123-45-6789", "219-09-9999", "457-55-5462"}


@dataclass
class Rule:
    """A single detection rule.

    Args:
        id: Stable identifier used in SARIF and suppressions (e.g. ``PHI001``).
        name: Short kebab-case name.
        severity: Base severity: ``low``, ``medium`` or ``high``.
        description: One-line explanation shown to reviewers.
        help: Remediation guidance.
    """

    id: str
    name: str
    severity: str
    description: str
    help: str


@dataclass
class Finding:
    """One possible PHI occurrence. ``masked`` never contains the full matched value."""

    rule: Rule
    path: str
    line: int
    column: int
    severity: str
    masked: str
    note: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    # Raw value is kept in memory only, for allow-list comparison. Never printed or serialized.
    raw: str = field(default="", repr=False)


@dataclass
class Config:
    """Scanner configuration loaded from JSON (all keys optional).

    Example ``.phi-scan.json``::

        {
          "exclude_paths": ["tests/fixtures/synthetic/**"],
          "synthetic_paths": ["**/synthea/**"],
          "allow_values": ["0500000000"],
          "disabled_rules": ["PHI006"]
        }
    """

    exclude_paths: list[str] = field(default_factory=list)
    synthetic_paths: list[str] = field(default_factory=lambda: [
        "**/synthetic/**", "**/synthea/**", "**/*synthetic*", "**/fake*/**", "**/mock*/**",
    ])
    allow_values: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Optional[Path]) -> "Config":
        """Load config from ``path``; missing file returns defaults.

        Raises:
            ValueError: if the file exists but is not a JSON object with known keys.
        """
        cfg = cls()
        if path is None or not path.is_file():
            return cfg
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: config must be a JSON object")
        known = {"exclude_paths", "synthetic_paths", "allow_values", "disabled_rules"}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"{path}: unknown keys {sorted(unknown)}")
        for key in known & set(data):
            value = data[key]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"{path}: '{key}' must be a list of strings")
            if key == "synthetic_paths":
                cfg.synthetic_paths = cfg.synthetic_paths + value
            else:
                setattr(cfg, key, value)
        return cfg


RULES = {
    r.id: r
    for r in [
        Rule("PHI001", "saudi-national-id-or-iqama", "high",
             "10-digit number starting with 1 (citizen) or 2 (resident/Iqama) that passes the "
             "Luhn check, next to an identity keyword.",
             "Replace with a synthetic identifier. If this is real, rotate the data out of git "
             "history and report it per your incident process."),
        Rule("PHI002", "saudi-id-shaped-number", "low",
             "10-digit number starting with 1 or 2 that passes the Luhn check, with no identity "
             "keyword nearby. Often a timestamp or other number; listed for review only.",
             "Confirm it is not a national ID or Iqama number; add an inline ignore if benign."),
        Rule("PHI003", "us-ssn", "high",
             "US Social Security Number format (AAA-GG-SSSS with invalid ranges excluded).",
             "Remove or replace with a value from the SSA-reserved 987-65-4320..4329 range."),
        Rule("PHI004", "saudi-mobile-number", "low",
             "Saudi mobile number (05xxxxxxxx / +9665xxxxxxxx). Raised to medium near patient terms.",
             "Use a placeholder such as 0500000000 in fixtures and docs."),
        Rule("PHI005", "email-address", "low",
             "Email address outside reserved example domains. Raised to medium near patient terms.",
             "Use addresses at example.com / example.org in fixtures and docs."),
        Rule("PHI006", "labelled-medical-record-number", "high",
             "A medical record number, patient ID or file number assigned a literal value.",
             "Fixtures should use clearly synthetic values; never commit identifiers from a "
             "real HIS/EMR."),
        Rule("PHI007", "labelled-date-of-birth", "medium",
             "A date of birth (Gregorian or Hijri) assigned a literal value.",
             "Use synthetic dates in fixtures; confirm the record is not real."),
        Rule("PHI008", "phi-in-log-statement", "medium",
             "A logging or print call that appears to include patient or contact fields.",
             "Log opaque IDs or redacted values only. Route PHI access to the audit log, not "
             "the application log."),
        Rule("PHI009", "fhir-patient-with-identifiers", "medium",
             "A FHIR Patient resource with identifier, name or birthDate values outside a "
             "synthetic-data path.",
             "Move synthetic fixtures under a synthetic/ path or generate them with Synthea; "
             "never commit exports from a production FHIR server."),
        Rule("PHI010", "clinical-data-file", "high",
             "A clinical payload file (HL7 v2, DICOM, NIfTI, C-CDA) or HL7 v2 message content "
             "with a PID segment.",
             "Keep clinical payloads out of git. Use de-identified samples stored outside the "
             "repository."),
    ]
}


# --------------------------------------------------------------------------- helpers

def luhn_valid(number: str) -> bool:
    """Return True if ``number`` (digits only) passes the Luhn mod-10 check.

    MEDICAL: The Saudi national ID / Iqama check digit is widely documented as Luhn over all
    10 digits. That is an assumption here, not verified against an official NIC/Absher spec.
    """
    if not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask(value: str) -> str:
    """Mask a matched value so logs and SARIF never carry it in full."""
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


def is_repetitive(digits: str) -> bool:
    """True for obvious placeholders like 0500000000 or 1111111111."""
    core = digits[-8:] if len(digits) >= 8 else digits
    return len(set(core)) <= 2


def bump(severity: str) -> str:
    idx = SEVERITIES.index(severity)
    return SEVERITIES[min(idx + 1, len(SEVERITIES) - 1)]


def path_matches(rel: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch("/" + rel, pat):
            return True
        # Let "dir/**" also match files directly inside the top-level dir.
        if pat.endswith("/**") and (rel + "/").startswith(pat[:-2].lstrip("*/")):
            return True
    return False


def iter_files(root: Path, cfg: Config) -> Iterator[tuple[Path, str]]:
    excludes = DEFAULT_EXCLUDES + cfg.exclude_paths
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [
            d for d in dirnames
            if not path_matches(f"{rel_dir}/{d}".lstrip("/") + "/x", excludes)
        ]
        for name in filenames:
            rel = f"{rel_dir}/{name}".lstrip("/")
            if not path_matches(rel, excludes):
                yield Path(dirpath) / name, rel


def read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def inline_suppression(lines: list[str], idx: int) -> Optional[str]:
    """Return the reason text if line ``idx`` or the line above carries phi-scan:ignore."""
    for j in (idx, idx - 1):
        if 0 <= j < len(lines) and INLINE_IGNORE in lines[j]:
            after = lines[j].split(INLINE_IGNORE, 1)[1].strip(" :-#/*>\t")
            return after or "inline ignore (no reason given)"
    return None


CONTEXT_CHARS = 80
GENERATED_EXTS = {".js", ".mjs", ".cjs", ".css"}


def context(lines: list[str], idx: int, start: int, end: int) -> str:
    """Text around a match: +/-80 characters on the line, plus neighbouring lines if short.

    A character window (not whole lines) keeps one 'patient' word in a minified bundle from
    raising the severity of every match in that bundle.
    """
    line = lines[idx]
    parts = [line[max(0, start - CONTEXT_CHARS): end + CONTEXT_CHARS]]
    for j in (idx - 1, idx + 1):
        if 0 <= j < len(lines) and len(lines[j]) <= 300:
            parts.append(lines[j])
    return "\n".join(parts)


def looks_generated(path: Path, text: str) -> bool:
    """Heuristic: minified/bundled JS or CSS (very long average line length)."""
    if path.suffix.lower() not in GENERATED_EXTS or not text:
        return False
    lines = text.count("\n") + 1
    return len(text) / lines > 500


# --------------------------------------------------------------------------- detectors

SAUDI_ID_RE = re.compile(r"(?<![\d.])([12]\d{9})(?![\d.])")
SSN_RE = re.compile(r"(?<![\d-])(?!000|666|9\d\d)(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})(?![\d-])")
SA_MOBILE_RE = re.compile(r"(?<![\d+])((?:\+966|00966|966)\s?5\d(?:[\s-]?\d){7}|05\d(?:[\s-]?\d){7})(?!\d)")
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
SAFE_EMAIL_DOMAINS = re.compile(
    r"(?i)@((\w+\.)*(example\.(com|org|net)|test|invalid|localhost|"
    r"users\.noreply\.github\.com|noreply\.github\.com))$"
)
MRN_RE = re.compile(
    r"(?i)\b(mrn|medical[_ -]?record[_ -]?(?:number|no|num)|patient[_ -]?(?:id|no|number)|"
    r"file[_ -]?(?:no|number)|رقم\s*الملف)\b[\"']?\s*[:=]>?\s*[\"']([A-Z0-9][A-Z0-9-]{4,})[\"']"
)
MRN_BARE_NUMBER_RE = re.compile(
    r"(?i)\b(mrn|medical[_ -]?record[_ -]?(?:number|no|num))\b[\"']?\s*[:=]>?\s*(\d{5,})\b"
)
DOB_RE = re.compile(
    r"(?i)\b(dob|date[_ -]?of[_ -]?birth|birth[_ -]?date|birthdate|تاريخ\s*الميلاد)\b[\"']?\s*[:=]>?\s*"
    r"[\"']?((?:19|20|13|14)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])|"
    r"(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20|13|14)\d{2})"
)
FHIR_PATIENT_RE = re.compile(r"\"resourceType\"\s*:\s*\"Patient\"")
FHIR_PATIENT_FIELDS_RE = re.compile(r"\"(identifier|birthDate|name|telecom|address)\"\s*:")
HL7_PID_RE = re.compile(r"(?m)^PID\|")
HL7_MSH_RE = re.compile(r"(?m)^MSH\|\^~\\&")


Detector = Callable[[str, list[str], str, Config], Iterator[Finding]]


def _finding(rule_id: str, rel: str, line_idx: int, col: int, value: str,
             severity: Optional[str] = None, note: str = "") -> Finding:
    rule = RULES[rule_id]
    return Finding(rule=rule, path=rel, line=line_idx + 1, column=col + 1,
                   severity=severity or rule.severity, masked=mask(value), note=note,
                   raw=value.strip())


def detect_line_patterns(rel: str, lines: list[str], text: str, cfg: Config) -> Iterator[Finding]:
    for i, line in enumerate(lines):
        def ctx(m: re.Match, group: int = 0) -> str:
            return context(lines, i, m.start(group), m.end(group))

        def patient_near(m: re.Match, group: int = 0) -> bool:
            return bool(PATIENT_CONTEXT.search(ctx(m, group)))

        for m in SAUDI_ID_RE.finditer(line):
            num = m.group(1)
            if not luhn_valid(num) or is_repetitive(num):
                continue
            c = ctx(m, 1)
            patient_ctx = bool(PATIENT_CONTEXT.search(c))
            if NATIONAL_ID_CONTEXT.search(c):
                yield _finding("PHI001", rel, i, m.start(1), num)
            elif not EPOCH_CONTEXT.search(c):
                sev = "medium" if patient_ctx else "low"
                yield _finding("PHI002", rel, i, m.start(1), num, severity=sev)

        for m in SSN_RE.finditer(line):
            value = m.group(0)
            if value in KNOWN_TEST_SSNS or value.startswith("987-65-432"):
                continue
            yield _finding("PHI003", rel, i, m.start(), value)

        for m in SA_MOBILE_RE.finditer(line):
            digits = re.sub(r"\D", "", m.group(1))
            if is_repetitive(digits) or digits.endswith("12345678"):
                continue
            sev = bump("low") if patient_near(m, 1) else "low"
            yield _finding("PHI004", rel, i, m.start(1), m.group(1), severity=sev)

        for m in EMAIL_RE.finditer(line):
            email = m.group(1)
            if SAFE_EMAIL_DOMAINS.search(email):
                continue
            sev = bump("low") if patient_near(m, 1) else "low"
            yield _finding("PHI005", rel, i, m.start(1), email, severity=sev)

        for regex in (MRN_RE, MRN_BARE_NUMBER_RE):
            for m in regex.finditer(line):
                value = m.group(2)
                if not any(c.isdigit() for c in value) or is_repetitive(re.sub(r"\D", "", value) or "0"):
                    continue
                yield _finding("PHI006", rel, i, m.start(2), value)

        for m in DOB_RE.finditer(line):
            yield _finding("PHI007", rel, i, m.start(2), m.group(2))

        for call in LOG_CALL.finditer(line):
            # Only look at the arguments right after the call, not the rest of a long line.
            args = line[call.end(): call.end() + 160]
            f = LOG_SENSITIVE_FIELD.search(args)
            if f:
                yield _finding("PHI008", rel, i, call.end() + f.start(), f.group(0),
                               note=f"log call references '{f.group(0)}'")
                break


def detect_file_level(rel: str, lines: list[str], text: str, cfg: Config) -> Iterator[Finding]:
    synthetic = path_matches(rel, cfg.synthetic_paths)
    if FHIR_PATIENT_RE.search(text) and FHIR_PATIENT_FIELDS_RE.search(text) and not synthetic:
        m = FHIR_PATIENT_RE.search(text)
        line_idx = text.count("\n", 0, m.start())
        yield Finding(rule=RULES["PHI009"], path=rel, line=line_idx + 1, column=1,
                      severity=RULES["PHI009"].severity, masked="resourceType=Patient",
                      note="FHIR Patient resource outside a synthetic-data path")
    if HL7_MSH_RE.search(text) and HL7_PID_RE.search(text):
        m = HL7_PID_RE.search(text)
        line_idx = text.count("\n", 0, m.start())
        yield Finding(rule=RULES["PHI010"], path=rel, line=line_idx + 1, column=1,
                      severity="medium" if synthetic else "high", masked="PID|…",
                      note="HL7 v2 message with a PID (patient identification) segment")


DETECTORS: list[Detector] = [detect_line_patterns, detect_file_level]


SKIPPED_GENERATED: list[str] = []


def scan(root: Path, cfg: Config) -> tuple[list[Finding], int]:
    """Scan ``root`` and return (findings, files_scanned).

    Suppressed findings are returned with ``suppressed=True`` so they can be reported.
    Minified bundles are skipped and listed in ``SKIPPED_GENERATED``; their sources are
    expected to be scanned instead.
    """
    findings: list[Finding] = []
    scanned = 0
    SKIPPED_GENERATED.clear()
    allow = set(cfg.allow_values)
    for path, rel in iter_files(root, cfg):
        ext = path.suffix.lower()
        if ext in CLINICAL_FILE_EXTENSIONS and "PHI010" not in cfg.disabled_rules:
            findings.append(Finding(
                rule=RULES["PHI010"], path=rel, line=1, column=1,
                severity="medium" if path_matches(rel, cfg.synthetic_paths) else "high",
                masked=ext, note=CLINICAL_FILE_EXTENSIONS[ext]))
            scanned += 1
            continue
        text = read_text(path)
        if text is None:
            continue
        if looks_generated(path, text):
            SKIPPED_GENERATED.append(rel)
            continue
        scanned += 1
        lines = text.splitlines()
        for detector in DETECTORS:
            for f in detector(rel, lines, text, cfg):
                if f.rule.id in cfg.disabled_rules:
                    continue
                reason = inline_suppression(lines, f.line - 1) if lines else None
                if reason:
                    f.suppressed, f.suppression_reason = True, reason
                elif f.raw and f.raw in allow:
                    f.suppressed, f.suppression_reason = True, "allow_values in config"
                findings.append(f)
    return findings, scanned


# --------------------------------------------------------------------------- output

def to_sarif(findings: list[Finding], root: Path) -> dict:
    """Build a SARIF 2.1.0 log. Only masked values are included."""
    used = sorted({f.rule.id for f in findings})
    rules = [
        {
            "id": RULES[rid].id,
            "name": RULES[rid].name,
            "shortDescription": {"text": RULES[rid].name},
            "fullDescription": {"text": RULES[rid].description},
            "help": {"text": RULES[rid].help},
            "defaultConfiguration": {"level": SARIF_LEVEL[RULES[rid].severity]},
            "properties": {
                "tags": ["security", "privacy", "phi", "hipaa"],
                "security-severity": SARIF_SECURITY_SEVERITY[RULES[rid].severity],
            },
        }
        for rid in used
    ]
    index = {rid: i for i, rid in enumerate(used)}
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"Possible PHI ({f.rule.name}): {f.masked}"
                                + (f" — {f.note}" if f.note else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
            "partialFingerprints": {"phiScan/v1": f"{f.rule.id}:{f.path}:{f.masked}"},
            "properties": {"security-severity": SARIF_SECURITY_SEVERITY[f.severity]},
        }
        if f.suppressed:
            result["suppressions"] = [{"kind": "inSource", "justification": f.suppression_reason}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "phi-scan",
                "version": __version__,
                "informationUri": "https://github.com/Fadil369/B.I.Lab/blob/main/docs/healthcare-security-scan.md",
                "rules": rules,
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": root.resolve().as_uri() + "/"}},
            "results": results,
        }],
    }


def print_report(findings: list[Finding], scanned: int, fail_on: str) -> None:
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    order = sorted(active, key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line))
    for f in order:
        gate = "FAIL" if SEVERITY_RANK[f.severity] >= SEVERITY_RANK[fail_on] else "info"
        print(f"[{gate}] {f.severity.upper():6} {f.rule.id} {f.path}:{f.line}:{f.column} "
              f"{f.rule.name} value={f.masked}" + (f" ({f.note})" if f.note else ""))
    counts = {s: sum(1 for f in active if f.severity == s) for s in SEVERITIES}
    print(f"\nphi-scan {__version__}: {scanned} files scanned, "
          f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
          f"{len(suppressed)} suppressed, {len(SKIPPED_GENERATED)} minified bundles skipped. "
          f"Fail threshold: {fail_on}.")
    if suppressed:
        print("Suppressed findings (review these periodically):")
        for f in suppressed:
            print(f"  {f.rule.id} {f.path}:{f.line} — {f.suppression_reason}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Flag possible PHI in a repository.")
    parser.add_argument("--root", default=".", help="Directory to scan (default: .)")
    parser.add_argument("--config", default=None,
                        help="JSON config path (default: <root>/.phi-scan.json if present)")
    parser.add_argument("--sarif", default=None, help="Write SARIF 2.1.0 output here")
    parser.add_argument("--fail-on", default="medium", choices=["low", "medium", "high", "none"],
                        help="Lowest severity that makes the exit code 1 (default: medium)")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    cfg_path = Path(args.config) if args.config else root / ".phi-scan.json"
    try:
        cfg = Config.load(cfg_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: bad config: {exc}", file=sys.stderr)
        return 2

    findings, scanned = scan(root, cfg)
    print_report(findings, scanned, args.fail_on)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings, root), indent=2), encoding="utf-8")

    failing = [f for f in findings
               if not f.suppressed and SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on]]
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
