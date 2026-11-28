#!/usr/bin/env python3
"""Biomedical & scientific research artifact verifier for BrainSAIT B.I.Lab.

Validates repository research outputs and provenance manifests across the four
Antigravity for Science pillars plus BrainSAIT / Zenodo RDM governance rules:

  1. Genomics (`genomics`):
     - VCF files (`.vcf`): `#CHROM\\tPOS\\tID\\tREF\\tALT` header, positive `POS`,
       canonical `ACGTN` bases, rsID syntax on populated `ID` fields.
     - Variant JSON / TSV manifests: `rs\\d+` rsIDs, HGVS notation, and `[0, 1]`
       bounds on AlphaGenome / ClinVar / allele-frequency scores.
  2. Structural Biology (`structural-biology`):
     - FASTA files (`.fasta`, `.fa`, `.faa`, `.fna`): non-empty sequence records
       and valid IUPAC amino-acid / nucleotide alphabets.
     - PDB files (`.pdb`): `ATOM` / `HETATM` coordinate records and `END` record.
     - AlphaFold / structure JSON metadata: `pLDDT` bounds in `[0, 100]`,
       UniProt accession syntax, and 4-char PDB identifiers.
  3. Chemistry / Cheminformatics (`chemistry`):
     - Molecular JSON / CSV / TSV manifests: non-empty SMILES with balanced
       parentheses, brackets, and closed ring-closure digits; InChIKey format
       `^[A-Z]{14}-[A-Z]{10}-[A-Z]$`; `CHEMBL\\d+` IDs; positive PubChem CIDs.
  4. Scientific Literature & Zenodo RDM Provenance (`literature-zenodo`):
     - `CITATION.cff` metadata (`cff-version`, `title`, `authors`, DOIs).
     - `zenodo_metadata.json` / `zenodo*.json` / `.zenodo.json`: enforces
       `metadata.title`, `metadata.upload_type`, `metadata.creators`, mandatory
       `metadata.publisher` for DataCite / Zenodo DOI registration, and valid
       `related_identifiers[].relation_type` / `relation` — explicitly catching
       invalid `isrelatedto` (which causes Zenodo HTTP 400 errors).
     - Literature & clinical-trial identifiers: DOI (`10.\\d{4,9}/...`), PMID,
       PMCID (`PMC\\d+`), and ClinicalTrials.gov (`NCT\\d{8}`).

Design rules:
  * Standard library only (Python 3.10+), zero third-party runtime dependencies.
  * Concise stdout summary strictly under 50 lines (matching Antigravity for
    Science output discipline); full details go to `--output` JSON.

Exit codes:
    0  no finding at or above `--fail-on`
    1  at least one finding at or above `--fail-on`
    2  CLI usage or filesystem configuration error

Examples:
    >>> is_valid_smiles("CC(=O)Oc1ccccc1C(=O)O")
    (True, '')
    >>> is_valid_smiles("c1ccccc")
    (False, 'unclosed ring digit(s): 1')
    >>> is_valid_inchikey("BSYNRYMUTXBXSQ-UHFFFAOYSA-N")
    True
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

__version__ = "1.0.0"

PILLARS = (
    "genomics",
    "structural-biology",
    "chemistry",
    "literature-zenodo",
)

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {"none": 99, "low": 0, "medium": 1, "high": 2}
MAX_STDOUT_FINDINGS = 18  # Guarantees total stdout stays well below 50 lines.
MAX_FILE_BYTES = 10 * 1024 * 1024

DEFAULT_EXCLUDES = (
    ".git/**",
    "**/.git/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "**/science-lab-report*.json",
    "**/bpr-verify-report*.json",
)

# Genomics patterns
VCF_REF_RE = re.compile(r"^[ACGTNacgtn]+$")
VCF_ALT_ALLELE_RE = re.compile(r"^(?:[ACGTNacgtn]+|\*|\.|<[^>\s]+>)$")
RSID_RE = re.compile(r"^rs[1-9]\d*$")
HGVS_RE = re.compile(
    r"^(?:NC_|NM_|NP_|NG_|NR_|LRG_|ENST|ENSP|ENSG|chr[0-9XYMUn_]+|[A-Za-z0-9_.]+):[cgpmnr]\.[A-Za-z0-9_>*+\-()?=\[\].]+$"
)
UNIT_INTERVAL_KEYS = {
    "alphagenome_score",
    "impact_score",
    "variant_impact_score",
    "clinvar_score",
    "pathogenicity_score",
    "spliceai_score",
    "gnomad_af",
    "allele_frequency",
}

# Structural biology patterns
FASTA_PROTEIN_OR_NA_RE = re.compile(r"^[ACDEFGHIKLMNPQRSTVWYBXZJUOacdefghiklmnpqrstvwybxzjuo*\-]+$")
FASTA_NUCLEOTIDE_RE = re.compile(r"^[ACGTURYKMSWBDHVNacgturykmswbdhvn\-]+$")
UNIPROT_RE = re.compile(
    r"^(?:[OPQ][0-9][A-Z0-9]{3}[0-9]|[A-NR-Z][0-9](?:[A-Z][A-Z0-9]{2}[0-9]){1,2})(?:-\d+)?$"
)
PDB_ID_RE = re.compile(r"^[0-9][A-Za-z0-9]{3}$")

# Chemistry patterns
INCHIKEY_RE = re.compile(r"^[A-Z]{14}-[A-Z]{10}-[A-Z]$")
CHEMBL_RE = re.compile(r"^CHEMBL[1-9]\d*$")
SMILES_ALLOWED_CHARS_RE = re.compile(r"^[A-Za-z0-9@+\-\[\]\(\)\\/=#$:.%*]+$")

# Scientific literature & Zenodo RDM patterns
DOI_RE = re.compile(r"^10\.\d{4,9}/[-._;()/:A-Za-z0-9]+$")
PMID_RE = re.compile(r"^(?:PMID:\s*)?[1-9]\d{0,9}$")
PMCID_RE = re.compile(r"^PMC[1-9]\d+$")
NCT_RE = re.compile(r"^NCT\d{8}$")

ZENODO_UPLOAD_TYPES = {
    "publication",
    "poster",
    "presentation",
    "dataset",
    "image",
    "video",
    "software",
    "lesson",
    "physicalobject",
    "other",
}

# Official Zenodo / DataCite REST vocabulary (normalized lowercase alphanumeric).
# Notably, `isrelatedto` is NOT accepted by Zenodo REST deposits and triggers HTTP 400.
VALID_ZENODO_RELATIONS = {
    "iscitedby",
    "cites",
    "issupplementto",
    "issupplementedby",
    "iscontinuedby",
    "continues",
    "isnewversionof",
    "ispreviousversionof",
    "ispartof",
    "haspart",
    "isreferencedby",
    "references",
    "isdocumentedby",
    "documents",
    "iscompiledby",
    "compiles",
    "isvariantformof",
    "isoriginalformof",
    "isidenticalto",
    "isreviewedby",
    "reviews",
    "isderivedfrom",
    "issourceof",
    "describes",
    "isdescribedby",
    "hasmetadata",
    "ismetadatafor",
    "requires",
    "isrequiredby",
    "obsoletes",
    "isobsoletedby",
}


@dataclass(frozen=True)
class Finding:
    """A single validation finding attributed to a file, line, and science pillar."""

    rule_id: str
    pillar: str
    severity: str
    path: str
    line: int
    message: str


def _rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _is_excluded(rel_path: str, excludes: Sequence[str]) -> bool:
    for pattern in excludes:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(rel_path, pattern[3:]):
            return True
    return False


def _iter_files(root: Path, excludes: Sequence[str] = DEFAULT_EXCLUDES) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in {".git", "node_modules", ".venv", "venv", "__pycache__"}
        )
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel = _rel_posix(fpath, root)
            if _is_excluded(rel, excludes):
                continue
            try:
                if fpath.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append(fpath)
    return found


def normalize_doi(raw: str) -> str:
    """Strip common URL or scheme prefixes before checking canonical DOI syntax."""
    val = raw.strip()
    for prefix in ("https://doi.org/", "http://doi.org/", "https://dx.doi.org/", "doi:", "DOI:"):
        if val.startswith(prefix):
            return val[len(prefix) :].strip()
    return val


def is_valid_inchikey(value: str) -> bool:
    """Return True if value matches standard 27-character IUPAC InChIKey syntax."""
    return bool(INCHIKEY_RE.match(value.strip()))


def is_valid_smiles(smiles: str) -> tuple[bool, str]:
    """Perform stdlib structural sanity checks on a SMILES string.

    Checks non-emptiness, absence of whitespace/illegal characters, balanced
    parentheses `()` and atom brackets `[]`, and paired ring-closure tokens
    (`1`-`9` and `%10`-`%99`) outside bracket expressions.
    """
    s = smiles.strip()
    if not s:
        return False, "SMILES string is empty"
    if any(ch.isspace() for ch in smiles):
        return False, "SMILES string contains whitespace"
    if not SMILES_ALLOWED_CHARS_RE.match(s):
        return False, "SMILES string contains invalid characters"

    paren_depth = 0
    in_bracket = False
    open_rings: set[str] = set()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_bracket:
            if ch == "[":
                return False, "nested '[' inside atom bracket"
            if ch == "]":
                in_bracket = False
            i += 1
            continue

        if ch == "[":
            in_bracket = True
            i += 1
            continue
        if ch == "]":
            return False, "unmatched ']' in SMILES"
        if ch == "(":
            paren_depth += 1
            i += 1
            continue
        if ch == ")":
            paren_depth -= 1
            if paren_depth < 0:
                return False, "unmatched ')' in SMILES"
            i += 1
            continue
        if ch == "%":
            if i + 2 >= n or not (s[i + 1].isdigit() and s[i + 2].isdigit()):
                return False, "malformed two-digit ring closure after '%'"
            ring_tok = s[i + 1 : i + 3]
            if ring_tok in open_rings:
                open_rings.remove(ring_tok)
            else:
                open_rings.add(ring_tok)
            i += 3
            continue
        if ch.isdigit():
            if ch == "0":
                return False, "ring closure digit '0' is invalid without '%'"
            if ch in open_rings:
                open_rings.remove(ch)
            else:
                open_rings.add(ch)
            i += 1
            continue
        i += 1

    if in_bracket:
        return False, "unclosed '[' atom bracket in SMILES"
    if paren_depth != 0:
        return False, "unbalanced parentheses in SMILES"
    if open_rings:
        return False, f"unclosed ring digit(s): {', '.join(sorted(open_rings))}"
    return True, ""


# ---------------------------------------------------------------------------
# Pillar 1: Genomics
# ---------------------------------------------------------------------------


def validate_vcf(path: Path, rel_path: str) -> list[Finding]:
    """Validate a VCF file header and variant rows."""
    findings: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    saw_header = False
    data_rows = 0
    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        if raw.startswith("##"):
            continue
        if raw.startswith("#"):
            expected_prefix = "#CHROM\tPOS\tID\tREF\tALT"
            if not raw.startswith(expected_prefix):
                findings.append(
                    Finding(
                        rule_id="GEN001",
                        pillar="genomics",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message="VCF header line must begin with '#CHROM\\tPOS\\tID\\tREF\\tALT'",
                    )
                )
            else:
                saw_header = True
            continue

        if not saw_header:
            findings.append(
                Finding(
                    rule_id="GEN001",
                    pillar="genomics",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message="VCF data record encountered before '#CHROM\\tPOS\\tID\\tREF\\tALT' header",
                )
            )
            saw_header = True  # Avoid repeating on every subsequent row.

        data_rows += 1
        cols = raw.split("\t")
        if len(cols) < 5:
            findings.append(
                Finding(
                    rule_id="GEN002",
                    pillar="genomics",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message=f"VCF record has {len(cols)} tab-separated column(s); expected at least 5",
                )
            )
            continue

        chrom, pos_str, var_id, ref, alt = cols[0], cols[1], cols[2], cols[3], cols[4]
        if not chrom.strip():
            findings.append(
                Finding("GEN002", "genomics", "high", rel_path, lineno, "VCF CHROM column is empty")
            )
        try:
            pos = int(pos_str)
            if pos < 1:
                raise ValueError("non-positive")
        except ValueError:
            findings.append(
                Finding(
                    rule_id="GEN003",
                    pillar="genomics",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message=f"VCF POS must be a positive integer >= 1 (got '{pos_str}')",
                )
            )

        if var_id and var_id != ".":
            for token in var_id.split(";"):
                if token.lower().startswith("rs") and not RSID_RE.match(token):
                    findings.append(
                        Finding(
                            rule_id="GEN005",
                            pillar="genomics",
                            severity="medium",
                            path=rel_path,
                            line=lineno,
                            message=f"Malformed dbSNP rsID '{token}' in VCF ID column (expected rs\\d+)",
                        )
                    )

        if not VCF_REF_RE.match(ref):
            findings.append(
                Finding(
                    rule_id="GEN004",
                    pillar="genomics",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message=f"Invalid VCF REF allele '{ref}' (allowed bases: A, C, G, T, N)",
                )
            )

        for allele in alt.split(","):
            if not VCF_ALT_ALLELE_RE.match(allele):
                findings.append(
                    Finding(
                        rule_id="GEN004",
                        pillar="genomics",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid VCF ALT allele '{allele}' (allowed bases: A, C, G, T, N, *, ., <SYM>)",
                    )
                )

    if not saw_header:
        findings.append(
            Finding(
                rule_id="GEN001",
                pillar="genomics",
                severity="high",
                path=rel_path,
                line=1,
                message="VCF file is missing mandatory '#CHROM\\tPOS\\tID\\tREF\\tALT' header",
            )
        )
    elif data_rows == 0:
        findings.append(
            Finding(
                rule_id="GEN002",
                pillar="genomics",
                severity="low",
                path=rel_path,
                line=1,
                message="VCF file contains a header but zero variant records",
            )
        )

    return findings


def _validate_variant_record(
    rec: dict[str, Any], rel_path: str, lineno: int
) -> list[Finding]:
    findings: list[Finding] = []
    lower_map = {str(k).strip().lower(): v for k, v in rec.items()}

    for key in ("rsid", "rs_id", "dbsnp_id"):
        val = lower_map.get(key)
        if val not in (None, "", "."):
            sval = str(val).strip()
            if not RSID_RE.match(sval):
                findings.append(
                    Finding(
                        rule_id="GEN005",
                        pillar="genomics",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid rsID '{sval}' in '{key}' (expected 'rs' followed by digits)",
                    )
                )

    for key in ("hgvs", "hgvsc", "hgvsp", "hgvsg"):
        val = lower_map.get(key)
        if val not in (None, "", "."):
            sval = str(val).strip()
            if not HGVS_RE.match(sval):
                findings.append(
                    Finding(
                        rule_id="GEN006",
                        pillar="genomics",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid HGVS expression '{sval}' in '{key}' (expected e.g. NM_007294.4:c.5266dupC)",
                    )
                )

    for key in UNIT_INTERVAL_KEYS:
        val = lower_map.get(key)
        if val not in (None, "", "."):
            try:
                fval = float(val)
                if not (0.0 <= fval <= 1.0):
                    findings.append(
                        Finding(
                            rule_id="GEN007",
                            pillar="genomics",
                            severity="high",
                            path=rel_path,
                            line=lineno,
                            message=f"Score '{key}={fval}' is out of bounds [0.0, 1.0]",
                        )
                    )
            except (TypeError, ValueError):
                findings.append(
                    Finding(
                        rule_id="GEN007",
                        pillar="genomics",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"Score '{key}={val}' must be numeric in [0.0, 1.0]",
                    )
                )

    if "pos" in lower_map and lower_map["pos"] not in (None, "", "."):
        try:
            if int(lower_map["pos"]) < 1:
                raise ValueError("non-positive")
        except (TypeError, ValueError):
            findings.append(
                Finding(
                    rule_id="GEN003",
                    pillar="genomics",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message=f"Variant position 'pos={lower_map['pos']}' must be a positive integer",
                )
            )

    for allele_key in ("ref", "alt"):
        aval = lower_map.get(allele_key)
        if aval not in (None, "", ".") and isinstance(aval, str):
            if not VCF_REF_RE.match(aval.strip()):
                findings.append(
                    Finding(
                        rule_id="GEN004",
                        pillar="genomics",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"Variant '{allele_key}={aval}' contains non-ACGTN bases",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Pillar 2: Structural Biology
# ---------------------------------------------------------------------------


def validate_fasta(path: Path, rel_path: str) -> list[Finding]:
    """Validate FASTA / FA sequence headers, non-empty sequences, and IUPAC alphabet."""
    findings: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    is_nucleotide_only = path.suffix.lower() == ".fna"
    alphabet_re = FASTA_NUCLEOTIDE_RE if is_nucleotide_only else FASTA_PROTEIN_OR_NA_RE

    records = 0
    current_header: str | None = None
    current_header_line = 1
    current_seq_len = 0

    for lineno, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith(">"):
            if current_header is not None and current_seq_len == 0:
                findings.append(
                    Finding(
                        rule_id="STR002",
                        pillar="structural-biology",
                        severity="high",
                        path=rel_path,
                        line=current_header_line,
                        message=f"FASTA record '{current_header}' has an empty sequence",
                    )
                )
            header_id = stripped[1:].strip()
            if not header_id:
                findings.append(
                    Finding(
                        rule_id="STR001",
                        pillar="structural-biology",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message="FASTA '>' header line has an empty sequence identifier",
                    )
                )
            current_header = header_id or "<unnamed>"
            current_header_line = lineno
            current_seq_len = 0
            records += 1
            continue

        if current_header is None:
            findings.append(
                Finding(
                    rule_id="STR001",
                    pillar="structural-biology",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message="FASTA sequence data encountered before initial '>' header line",
                )
            )
            current_header = "<missing-header>"
            current_header_line = lineno
            records += 1

        if not alphabet_re.match(stripped):
            findings.append(
                Finding(
                    rule_id="STR003",
                    pillar="structural-biology",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message="FASTA sequence contains invalid non-IUPAC residue/base characters",
                )
            )
        current_seq_len += len(stripped.replace("-", "").replace("*", ""))

    if records == 0:
        findings.append(
            Finding(
                rule_id="STR001",
                pillar="structural-biology",
                severity="high",
                path=rel_path,
                line=1,
                message="FASTA file contains zero sequence records",
            )
        )
    elif current_header is not None and current_seq_len == 0:
        findings.append(
            Finding(
                rule_id="STR002",
                pillar="structural-biology",
                severity="high",
                path=rel_path,
                line=current_header_line,
                message=f"FASTA record '{current_header}' has an empty sequence",
            )
        )

    return findings


def validate_pdb(path: Path, rel_path: str) -> list[Finding]:
    """Validate PDB coordinate records (ATOM/HETATM) and trailing END marker."""
    findings: list[Finding] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    atom_count = 0
    saw_end = False
    for lineno, raw in enumerate(lines, start=1):
        rec_type = raw[:6].strip()
        if rec_type in {"ATOM", "HETATM"}:
            atom_count += 1
            if len(raw) < 54:
                findings.append(
                    Finding(
                        rule_id="STR005",
                        pillar="structural-biology",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"PDB {rec_type} record is truncated (< 54 columns for X/Y/Z coordinates)",
                    )
                )
                continue
            try:
                float(raw[30:38].strip())
                float(raw[38:46].strip())
                float(raw[46:54].strip())
            except ValueError:
                findings.append(
                    Finding(
                        rule_id="STR005",
                        pillar="structural-biology",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"PDB {rec_type} record has non-numeric X/Y/Z coordinates in columns 31-54",
                    )
                )
        elif rec_type == "END":
            saw_end = True

    if atom_count == 0:
        findings.append(
            Finding(
                rule_id="STR004",
                pillar="structural-biology",
                severity="high",
                path=rel_path,
                line=1,
                message="PDB file contains zero ATOM or HETATM coordinate records",
            )
        )
    if not saw_end:
        findings.append(
            Finding(
                rule_id="STR006",
                pillar="structural-biology",
                severity="medium",
                path=rel_path,
                line=max(1, len(lines)),
                message="PDB file is missing terminal 'END' record",
            )
        )

    return findings


def _validate_structure_record(
    rec: dict[str, Any], rel_path: str, lineno: int
) -> list[Finding]:
    findings: list[Finding] = []
    lower_map = {str(k).strip().lower(): v for k, v in rec.items()}

    for key in ("plddt", "mean_plddt", "global_plddt"):
        val = lower_map.get(key)
        if val is not None and val != "":
            values = val if isinstance(val, list) else [val]
            for item in values:
                try:
                    fval = float(item)
                    if not (0.0 <= fval <= 100.0):
                        findings.append(
                            Finding(
                                rule_id="STR007",
                                pillar="structural-biology",
                                severity="high",
                                path=rel_path,
                                line=lineno,
                                message=f"AlphaFold confidence '{key}={fval}' is outside valid pLDDT range [0, 100]",
                            )
                        )
                        break
                except (TypeError, ValueError):
                    findings.append(
                        Finding(
                            rule_id="STR007",
                            pillar="structural-biology",
                            severity="high",
                            path=rel_path,
                            line=lineno,
                            message=f"AlphaFold confidence '{key}={item}' must be numeric in [0, 100]",
                        )
                    )
                    break

    if isinstance(lower_map.get("per_residue_plddt"), list):
        for item in lower_map["per_residue_plddt"]:
            try:
                fval = float(item)
                if not (0.0 <= fval <= 100.0):
                    findings.append(
                        Finding(
                            rule_id="STR007",
                            pillar="structural-biology",
                            severity="high",
                            path=rel_path,
                            line=lineno,
                            message=f"Residue pLDDT value {fval} is outside [0, 100]",
                        )
                    )
                    break
            except (TypeError, ValueError):
                findings.append(
                    Finding(
                        rule_id="STR007",
                        pillar="structural-biology",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"Residue pLDDT value '{item}' must be numeric",
                    )
                )
                break

    for key in ("uniprot_id", "uniprot_accession", "uniprot"):
        val = lower_map.get(key)
        if val not in (None, ""):
            sval = str(val).strip()
            if not UNIPROT_RE.match(sval):
                findings.append(
                    Finding(
                        rule_id="STR008",
                        pillar="structural-biology",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid UniProt accession '{sval}' in '{key}'",
                    )
                )

    if lower_map.get("pdb_id") not in (None, ""):
        pdb_id = str(lower_map["pdb_id"]).strip()
        if not PDB_ID_RE.match(pdb_id):
            findings.append(
                Finding(
                    rule_id="STR009",
                    pillar="structural-biology",
                    severity="medium",
                    path=rel_path,
                    line=lineno,
                    message=f"Invalid 4-character PDB identifier '{pdb_id}'",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Pillar 3: Chemistry / Cheminformatics
# ---------------------------------------------------------------------------


def _validate_molecule_record(
    rec: dict[str, Any], rel_path: str, lineno: int, require_smiles: bool = False
) -> list[Finding]:
    findings: list[Finding] = []
    lower_map = {str(k).strip().lower(): v for k, v in rec.items()}

    if "smiles" in lower_map or require_smiles:
        raw_smiles = lower_map.get("smiles")
        if raw_smiles is None or str(raw_smiles).strip() == "":
            findings.append(
                Finding(
                    rule_id="CHM001",
                    pillar="chemistry",
                    severity="high",
                    path=rel_path,
                    line=lineno,
                    message="Missing or empty 'smiles' field in molecular manifest",
                )
            )
        else:
            ok, reason = is_valid_smiles(str(raw_smiles))
            if not ok:
                findings.append(
                    Finding(
                        rule_id="CHM001",
                        pillar="chemistry",
                        severity="high",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid SMILES '{raw_smiles}': {reason}",
                    )
                )

    for key in ("inchikey", "inchi_key"):
        val = lower_map.get(key)
        if val not in (None, ""):
            sval = str(val).strip()
            if not is_valid_inchikey(sval):
                findings.append(
                    Finding(
                        rule_id="CHM002",
                        pillar="chemistry",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid InChIKey '{sval}' (expected ^[A-Z]{{14}}-[A-Z]{{10}}-[A-Z]$)",
                    )
                )

    for key in ("chembl_id", "chembl"):
        val = lower_map.get(key)
        if val not in (None, ""):
            sval = str(val).strip()
            if not CHEMBL_RE.match(sval):
                findings.append(
                    Finding(
                        rule_id="CHM003",
                        pillar="chemistry",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid ChEMBL ID '{sval}' (expected CHEMBL\\d+)",
                    )
                )

    for key in ("pubchem_cid", "cid"):
        val = lower_map.get(key)
        if val not in (None, ""):
            sval = str(val).strip()
            try:
                cid = int(sval)
                if cid < 1 or str(cid) != sval:
                    raise ValueError("not positive integer")
            except ValueError:
                findings.append(
                    Finding(
                        rule_id="CHM004",
                        pillar="chemistry",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid PubChem CID '{sval}' (expected positive integer)",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Pillar 4: Scientific Literature & Zenodo RDM Provenance
# ---------------------------------------------------------------------------


def _validate_literature_identifiers(
    rec: dict[str, Any], rel_path: str, lineno: int
) -> list[Finding]:
    findings: list[Finding] = []
    lower_map = {str(k).strip().lower(): v for k, v in rec.items()}

    if lower_map.get("doi") not in (None, ""):
        doi = normalize_doi(str(lower_map["doi"]))
        if not DOI_RE.match(doi):
            findings.append(
                Finding(
                    rule_id="LIT005",
                    pillar="literature-zenodo",
                    severity="medium",
                    path=rel_path,
                    line=lineno,
                    message=f"Invalid DOI '{lower_map['doi']}' (expected 10.<registrant>/<suffix>)",
                )
            )

    if lower_map.get("pmid") not in (None, ""):
        pmid = str(lower_map["pmid"]).strip()
        if not PMID_RE.match(pmid):
            findings.append(
                Finding(
                    rule_id="LIT006",
                    pillar="literature-zenodo",
                    severity="medium",
                    path=rel_path,
                    line=lineno,
                    message=f"Invalid PubMed PMID '{pmid}' (expected positive numeric ID)",
                )
            )

    if lower_map.get("pmcid") not in (None, ""):
        pmcid = str(lower_map["pmcid"]).strip()
        if not PMCID_RE.match(pmcid):
            findings.append(
                Finding(
                    rule_id="LIT007",
                    pillar="literature-zenodo",
                    severity="medium",
                    path=rel_path,
                    line=lineno,
                    message=f"Invalid Europe PMC / PubMed Central ID '{pmcid}' (expected PMC\\d+)",
                )
            )

    for key in ("nct_id", "nct", "clinical_trial_id", "trial_id"):
        val = lower_map.get(key)
        if val not in (None, ""):
            sval = str(val).strip()
            if key in {"nct_id", "nct", "clinical_trial_id"} or sval.upper().startswith("NCT"):
                if not NCT_RE.match(sval):
                    findings.append(
                        Finding(
                            rule_id="LIT008",
                            pillar="literature-zenodo",
                            severity="medium",
                            path=rel_path,
                            line=lineno,
                            message=f"Invalid ClinicalTrials.gov identifier '{sval}' (expected NCT\\d{{8}})",
                        )
                    )

    return findings


def validate_citation_cff(path: Path, rel_path: str) -> list[Finding]:
    """Validate CITATION.cff required keys and DOI syntax without PyYAML."""
    findings: list[Finding] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    top_keys: dict[str, tuple[int, str]] = {}
    has_author_item = False
    in_authors = False

    for lineno, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0 and ":" in stripped:
            key, _, rest = stripped.partition(":")
            k = key.strip()
            v = rest.strip().strip("\"'")
            top_keys[k] = (lineno, v)
            in_authors = k == "authors"
            continue

        if in_authors and stripped.startswith("-"):
            has_author_item = True

        # Check inline `doi:` or `value:` following `type: doi`
        m_doi = re.match(r"^doi:\s*(.+)$", stripped)
        if m_doi:
            raw_doi = m_doi.group(1).strip().strip("\"'")
            if raw_doi and not DOI_RE.match(normalize_doi(raw_doi)):
                findings.append(
                    Finding(
                        rule_id="LIT005",
                        pillar="literature-zenodo",
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"Invalid DOI '{raw_doi}' in CITATION.cff",
                    )
                )

    for req_key in ("cff-version", "title"):
        if req_key not in top_keys or not top_keys[req_key][1]:
            findings.append(
                Finding(
                    rule_id="LIT001",
                    pillar="literature-zenodo",
                    severity="high",
                    path=rel_path,
                    line=top_keys.get(req_key, (1, ""))[0],
                    message=f"CITATION.cff is missing required non-empty '{req_key}' field",
                )
            )

    if "authors" not in top_keys or not has_author_item:
        findings.append(
            Finding(
                rule_id="LIT001",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=top_keys.get("authors", (1, ""))[0],
                message="CITATION.cff must declare a non-empty 'authors' list",
            )
        )

    return findings


def validate_zenodo_json(path: Path, rel_path: str) -> list[Finding]:
    """Validate Zenodo / BrainSAIT RDM deposit metadata JSON."""
    findings: list[Finding] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=exc.lineno,
                message=f"Malformed JSON in Zenodo metadata file: {exc.msg}",
            )
        ]

    if not isinstance(payload, dict):
        return [
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=1,
                message="Zenodo metadata root must be a JSON object",
            )
        ]

    # Support both `{"metadata": {...}}` (Zenodo REST API deposit) and flat `.zenodo.json`.
    if "metadata" in payload:
        if not isinstance(payload["metadata"], dict):
            return [
                Finding(
                    rule_id="LIT002",
                    pillar="literature-zenodo",
                    severity="high",
                    path=rel_path,
                    line=1,
                    message="Zenodo 'metadata' property must be a JSON object",
                )
            ]
        meta = payload["metadata"]
    elif path.name == "zenodo_metadata.json":
        findings.append(
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="medium",
                path=rel_path,
                line=1,
                message="zenodo_metadata.json should wrap fields under a top-level 'metadata' object for Zenodo REST API deposits",
            )
        )
        meta = payload
    else:
        meta = payload

    title = meta.get("title")
    if not isinstance(title, str) or not title.strip():
        findings.append(
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=1,
                message="Zenodo metadata is missing non-empty 'metadata.title'",
            )
        )

    upload_type = meta.get("upload_type")
    resource_type = meta.get("resource_type")
    if upload_type is not None:
        if not isinstance(upload_type, str) or upload_type.strip().lower() not in ZENODO_UPLOAD_TYPES:
            findings.append(
                Finding(
                    rule_id="LIT002",
                    pillar="literature-zenodo",
                    severity="high",
                    path=rel_path,
                    line=1,
                    message=f"Invalid Zenodo 'metadata.upload_type'='{upload_type}' (allowed: {', '.join(sorted(ZENODO_UPLOAD_TYPES))})",
                )
            )
    elif not (isinstance(resource_type, (str, dict)) and resource_type):
        findings.append(
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=1,
                message="Zenodo metadata is missing required 'metadata.upload_type'",
            )
        )

    creators = meta.get("creators")
    if not isinstance(creators, list) or len(creators) == 0:
        findings.append(
            Finding(
                rule_id="LIT002",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=1,
                message="Zenodo metadata must provide a non-empty 'metadata.creators' list",
            )
        )
    else:
        for idx, creator in enumerate(creators, start=1):
            if not isinstance(creator, dict):
                findings.append(
                    Finding(
                        rule_id="LIT002",
                        pillar="literature-zenodo",
                        severity="high",
                        path=rel_path,
                        line=1,
                        message=f"Zenodo creator #{idx} must be an object",
                    )
                )
                continue
            has_name = bool(str(creator.get("name", "")).strip()) or bool(
                isinstance(creator.get("person_or_org"), dict)
                and str(creator["person_or_org"].get("name", "")).strip()
            )
            if not has_name:
                findings.append(
                    Finding(
                        rule_id="LIT002",
                        pillar="literature-zenodo",
                        severity="high",
                        path=rel_path,
                        line=1,
                        message=f"Zenodo creator #{idx} is missing required 'name'",
                    )
                )

    # BrainSAIT / DataCite v4.x DOI registration rule: mandatory `metadata.publisher`
    publisher = meta.get("publisher")
    if not isinstance(publisher, str) or not publisher.strip():
        findings.append(
            Finding(
                rule_id="LIT003",
                pillar="literature-zenodo",
                severity="high",
                path=rel_path,
                line=1,
                message="Zenodo metadata is missing mandatory 'metadata.publisher' required for BrainSAIT / DataCite DOI registration",
            )
        )

    # Validate related_identifiers and explicitly reject `isrelatedto` (Zenodo HTTP 400 trap)
    rel_ids = meta.get("related_identifiers")
    if rel_ids is not None:
        if not isinstance(rel_ids, list):
            findings.append(
                Finding(
                    rule_id="LIT004",
                    pillar="literature-zenodo",
                    severity="high",
                    path=rel_path,
                    line=1,
                    message="Zenodo 'metadata.related_identifiers' must be a list",
                )
            )
        else:
            for idx, entry in enumerate(rel_ids, start=1):
                if not isinstance(entry, dict):
                    findings.append(
                        Finding(
                            rule_id="LIT004",
                            pillar="literature-zenodo",
                            severity="high",
                            path=rel_path,
                            line=1,
                            message=f"related_identifiers[{idx}] must be an object",
                        )
                    )
                    continue

                raw_rel = entry.get("relation_type")
                if isinstance(raw_rel, dict):
                    raw_rel = raw_rel.get("id", "")
                if raw_rel is None:
                    raw_rel = entry.get("relation", "")
                norm_rel = re.sub(r"[\s_-]+", "", str(raw_rel).strip().lower())

                if norm_rel == "isrelatedto":
                    findings.append(
                        Finding(
                            rule_id="LIT004",
                            pillar="literature-zenodo",
                            severity="high",
                            path=rel_path,
                            line=1,
                            message=(
                                f"related_identifiers[{idx}] uses invalid relation '{raw_rel}' ('isrelatedto' is "
                                "rejected by Zenodo REST API with HTTP 400; use a specific DataCite relation "
                                "such as 'issupplementto', 'ispartof', 'cites', or 'isderivedfrom')"
                            ),
                        )
                    )
                elif not norm_rel or norm_rel not in VALID_ZENODO_RELATIONS:
                    findings.append(
                        Finding(
                            rule_id="LIT004",
                            pillar="literature-zenodo",
                            severity="high",
                            path=rel_path,
                            line=1,
                            message=f"related_identifiers[{idx}] has unsupported Zenodo relation '{raw_rel}'",
                        )
                    )

                ident = str(entry.get("identifier", "")).strip()
                scheme = str(entry.get("scheme", "")).strip().lower()
                if not ident:
                    findings.append(
                        Finding(
                            rule_id="LIT004",
                            pillar="literature-zenodo",
                            severity="medium",
                            path=rel_path,
                            line=1,
                            message=f"related_identifiers[{idx}] is missing non-empty 'identifier'",
                        )
                    )
                elif scheme == "doi" or ident.startswith(("10.", "https://doi.org/", "doi:")):
                    if not DOI_RE.match(normalize_doi(ident)):
                        findings.append(
                            Finding(
                                rule_id="LIT005",
                                pillar="literature-zenodo",
                                severity="medium",
                                path=rel_path,
                                line=1,
                                message=f"related_identifiers[{idx}] has malformed DOI '{ident}'",
                            )
                        )
                elif scheme == "pmid":
                    if not PMID_RE.match(ident):
                        findings.append(
                            Finding(
                                rule_id="LIT006",
                                pillar="literature-zenodo",
                                severity="medium",
                                path=rel_path,
                                line=1,
                                message=f"related_identifiers[{idx}] has malformed PMID '{ident}'",
                            )
                        )
                elif scheme == "pmcid" or ident.startswith("PMC"):
                    if not PMCID_RE.match(ident):
                        findings.append(
                            Finding(
                                rule_id="LIT007",
                                pillar="literature-zenodo",
                                severity="medium",
                                path=rel_path,
                                line=1,
                                message=f"related_identifiers[{idx}] has malformed PMCID '{ident}'",
                            )
                        )

    findings.extend(_validate_literature_identifiers(meta, rel_path, 1))
    return findings


# ---------------------------------------------------------------------------
# Structured tabular & JSON manifest dispatch
# ---------------------------------------------------------------------------


def _extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for list_key in (
            "variants",
            "records",
            "molecules",
            "compounds",
            "ligands",
            "structures",
            "predictions",
            "citations",
            "references",
            "studies",
            "trials",
            "items",
        ):
            if isinstance(payload.get(list_key), list):
                return [item for item in payload[list_key] if isinstance(item, dict)]
        return [payload]
    return []


def _classify_manifest_pillars(
    filename_lower: str, sample_keys: set[str]
) -> set[str]:
    matched: set[str] = set()
    if any(tok in filename_lower for tok in ("variant", "genom", "alphagenome", "clinvar", "gnomad")) or (
        sample_keys
        & {
            "rsid",
            "rs_id",
            "hgvs",
            "hgvsc",
            "hgvsp",
            "alphagenome_score",
            "clinvar_score",
            "variant_impact_score",
            "gnomad_af",
        }
    ):
        matched.add("genomics")

    if any(tok in filename_lower for tok in ("alphafold", "plddt", "uniprot", "structure", "foldseek")) or (
        sample_keys & {"plddt", "mean_plddt", "per_residue_plddt", "uniprot_id", "uniprot_accession"}
    ):
        matched.add("structural-biology")

    if any(tok in filename_lower for tok in ("molecule", "compound", "ligand", "smiles", "chembl", "cheminf")) or (
        sample_keys & {"smiles", "inchikey", "inchi_key", "chembl_id", "pubchem_cid"}
    ):
        matched.add("chemistry")

    if any(tok in filename_lower for tok in ("literature", "citation", "reference", "pubmed", "trial", "europepmc")) or (
        sample_keys & {"pmid", "pmcid", "nct_id", "clinical_trial_id"}
    ):
        matched.add("literature-zenodo")

    return matched


def validate_tabular_manifest(
    path: Path, rel_path: str, active_pillars: set[str]
) -> tuple[list[Finding], set[str]]:
    """Validate CSV / TSV manifests for genomics, chemistry, or literature columns."""
    findings: list[Finding] = []
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return findings, set()

    reader = csv.DictReader(lines, delimiter=delimiter)
    if not reader.fieldnames:
        return findings, set()

    header_keys = {h.strip().lower() for h in reader.fieldnames if h}
    pillars = _classify_manifest_pillars(path.name.lower(), header_keys) & active_pillars
    if not pillars:
        return findings, set()

    chem_require_smiles = "chemistry" in pillars and "smiles" in header_keys
    for row_idx, row in enumerate(reader, start=2):
        clean_row = {k: v for k, v in row.items() if k is not None}
        if "genomics" in pillars:
            findings.extend(_validate_variant_record(clean_row, rel_path, row_idx))
        if "structural-biology" in pillars:
            findings.extend(_validate_structure_record(clean_row, rel_path, row_idx))
        if "chemistry" in pillars:
            findings.extend(
                _validate_molecule_record(
                    clean_row, rel_path, row_idx, require_smiles=chem_require_smiles
                )
            )
        if "literature-zenodo" in pillars:
            findings.extend(_validate_literature_identifiers(clean_row, rel_path, row_idx))

    return findings, pillars


def validate_json_manifest(
    path: Path, rel_path: str, active_pillars: set[str]
) -> tuple[list[Finding], set[str]]:
    """Validate scientific JSON manifests across enabled pillars."""
    fname = path.name.lower()
    if fname == ".zenodo.json" or fname.startswith("zenodo"):
        if "literature-zenodo" not in active_pillars:
            return [], set()
        return validate_zenodo_json(path, rel_path), {"literature-zenodo"}

    # Skip well-known non-scientific config files quickly.
    if fname in {
        "package.json",
        "tsconfig.json",
        ".phi-scan.json",
        "devcontainer.json",
        "composer.json",
    }:
        return [], set()

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        # Only report malformed JSON if the filename explicitly targets a science manifest.
        explicit_pillars = _classify_manifest_pillars(fname, set()) & active_pillars
        if explicit_pillars:
            pillar = sorted(explicit_pillars)[0]
            return [
                Finding(
                    rule_id="SCI000",
                    pillar=pillar,
                    severity="high",
                    path=rel_path,
                    line=exc.lineno,
                    message=f"Malformed JSON in scientific manifest: {exc.msg}",
                )
            ], explicit_pillars
        return [], set()

    records = _extract_records(payload)
    if not records:
        explicit_pillars = _classify_manifest_pillars(fname, set()) & active_pillars
        return [], explicit_pillars

    sample_keys: set[str] = set()
    for rec in records[:10]:
        sample_keys.update(str(k).strip().lower() for k in rec.keys())

    pillars = _classify_manifest_pillars(fname, sample_keys) & active_pillars
    if not pillars:
        return [], set()

    findings: list[Finding] = []
    chem_named = any(tok in fname for tok in ("molecule", "compound", "ligand", "smiles"))
    for idx, rec in enumerate(records, start=1):
        if "genomics" in pillars:
            findings.extend(_validate_variant_record(rec, rel_path, idx))
        if "structural-biology" in pillars:
            findings.extend(_validate_structure_record(rec, rel_path, idx))
        if "chemistry" in pillars:
            findings.extend(
                _validate_molecule_record(rec, rel_path, idx, require_smiles=chem_named)
            )
        if "literature-zenodo" in pillars:
            findings.extend(_validate_literature_identifiers(rec, rel_path, idx))

    return findings, pillars


# ---------------------------------------------------------------------------
# Repository scan & reporting
# ---------------------------------------------------------------------------


def scan_repository(
    root: Path,
    *,
    require_citation: bool = False,
    pillars: Sequence[str] = PILLARS,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
) -> dict[str, Any]:
    """Scan a repository tree and return a structured verification report dictionary."""
    active_pillars = set(pillars)
    files = _iter_files(root, excludes=excludes)

    findings: list[Finding] = []
    checked_by_pillar: dict[str, list[str]] = {p: [] for p in PILLARS}
    saw_provenance_file = False

    for fpath in files:
        rel = _rel_posix(fpath, root)
        fname = fpath.name
        fname_lower = fname.lower()
        suffix = fpath.suffix.lower()

        if fname == "CITATION.cff":
            saw_provenance_file = True
            if "literature-zenodo" in active_pillars:
                checked_by_pillar["literature-zenodo"].append(rel)
                findings.extend(validate_citation_cff(fpath, rel))
            continue

        if fname_lower == ".zenodo.json" or (
            fname_lower.startswith("zenodo") and suffix == ".json"
        ):
            saw_provenance_file = True
            if "literature-zenodo" in active_pillars:
                checked_by_pillar["literature-zenodo"].append(rel)
                findings.extend(validate_zenodo_json(fpath, rel))
            continue

        if suffix == ".vcf" and "genomics" in active_pillars:
            checked_by_pillar["genomics"].append(rel)
            findings.extend(validate_vcf(fpath, rel))
            continue

        if suffix in {".fasta", ".fa", ".faa", ".fna"} and "structural-biology" in active_pillars:
            checked_by_pillar["structural-biology"].append(rel)
            findings.extend(validate_fasta(fpath, rel))
            continue

        if suffix == ".pdb" and "structural-biology" in active_pillars:
            checked_by_pillar["structural-biology"].append(rel)
            findings.extend(validate_pdb(fpath, rel))
            continue

        if suffix in {".csv", ".tsv"}:
            f_list, matched = validate_tabular_manifest(fpath, rel, active_pillars)
            for p in matched:
                checked_by_pillar[p].append(rel)
            findings.extend(f_list)
            continue

        if suffix == ".json":
            f_list, matched = validate_json_manifest(fpath, rel, active_pillars)
            for p in matched:
                checked_by_pillar[p].append(rel)
            findings.extend(f_list)
            continue

    if require_citation and "literature-zenodo" in active_pillars and not saw_provenance_file:
        findings.insert(
            0,
            Finding(
                rule_id="LIT000",
                pillar="literature-zenodo",
                severity="high",
                path=".",
                line=1,
                message=(
                    "Missing research citation provenance (--require-citation): "
                    "add CITATION.cff or zenodo_metadata.json"
                ),
            ),
        )

    # Order findings so highest-severity issues always appear first in concise stdout.
    findings.sort(key=lambda item: -SEVERITY_RANK[item.severity])

    severity_counts = {sev: 0 for sev in SEVERITIES}
    pillar_summary: dict[str, dict[str, Any]] = {}
    for p in PILLARS:
        p_findings = [f for f in findings if f.pillar == p]
        pillar_summary[p] = {
            "enabled": p in active_pillars,
            "files_checked": len(checked_by_pillar[p]),
            "findings": len(p_findings),
            "high": sum(1 for f in p_findings if f.severity == "high"),
            "medium": sum(1 for f in p_findings if f.severity == "medium"),
            "low": sum(1 for f in p_findings if f.severity == "low"),
        }

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    unique_checked = {rel for paths in checked_by_pillar.values() for rel in paths}
    return {
        "schema_version": "1.0",
        "tool": "science_lab_verify",
        "version": __version__,
        "root": str(root),
        "require_citation": require_citation,
        "pillars_enabled": [p for p in PILLARS if p in active_pillars],
        "summary": {
            "total_files_checked": len(unique_checked),
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_pillar": pillar_summary,
        },
        "artifacts_checked": checked_by_pillar,
        "findings": [asdict(f) for f in findings],
    }


def should_fail(report: dict[str, Any], fail_on: str) -> bool:
    threshold = SEVERITY_RANK[fail_on]
    if threshold >= SEVERITY_RANK["none"]:
        return False
    for f in report["findings"]:
        if SEVERITY_RANK[f["severity"]] >= threshold:
            return True
    return False


def format_stdout_summary(
    report: dict[str, Any], fail_on: str, output_path: str | None
) -> str:
    """Render a concise (<50 lines) stdout summary table and top findings."""
    lines: list[str] = []
    passed = not should_fail(report, fail_on)
    status_label = "PASS" if passed else "FAIL"
    summary = report["summary"]
    sev = summary["by_severity"]

    lines.append(
        f"science-lab-verify v{report['version']} [{status_label}] "
        f"files={summary['total_files_checked']} "
        f"findings={summary['total_findings']} "
        f"(high={sev['high']}, medium={sev['medium']}, low={sev['low']}, fail-on={fail_on})"
    )
    for pillar in PILLARS:
        ps = summary["by_pillar"][pillar]
        if not ps["enabled"]:
            continue
        lines.append(
            f"  - {pillar:18s}: checked={ps['files_checked']:3d}  "
            f"findings={ps['findings']:3d} (H:{ps['high']} M:{ps['medium']} L:{ps['low']})"
        )

    findings = report["findings"]
    if findings:
        lines.append("Findings:")
        for item in findings[:MAX_STDOUT_FINDINGS]:
            lines.append(
                f"  [{item['severity'].upper():6s}] {item['rule_id']} "
                f"{item['path']}:{item['line']} — {item['message']}"
            )
        remaining = len(findings) - MAX_STDOUT_FINDINGS
        if remaining > 0:
            lines.append(
                f"  ... {remaining} additional finding(s) omitted from stdout (see JSON report)."
            )

    if output_path:
        lines.append(f"Report written to: {output_path}")

    return "\n".join(lines) + "\n"


def format_markdown_summary(report: dict[str, Any], fail_on: str) -> str:
    """Render a GitHub Step Summary Markdown table for CI workflows."""
    passed = not should_fail(report, fail_on)
    badge = "PASS" if passed else "FAIL"
    summary = report["summary"]
    lines = [
        f"## Antigravity Science Lab Verification (`{badge}`)",
        "",
        "| Pillar | Files Checked | High | Medium | Low |",
        "|---|---:|---:|---:|---:|",
    ]
    for pillar in PILLARS:
        ps = summary["by_pillar"][pillar]
        if not ps["enabled"]:
            continue
        lines.append(
            f"| `{pillar}` | {ps['files_checked']} | {ps['high']} | {ps['medium']} | {ps['low']} |"
        )
    lines.append("")
    if report["findings"]:
        lines.append("### Findings")
        lines.append("")
        for item in report["findings"][:25]:
            lines.append(
                f"- **[{item['severity'].upper()}] `{item['rule_id']}`** "
                f"`{item['path']}:{item['line']}` — {item['message']}"
            )
        if len(report["findings"]) > 25:
            lines.append(
                f"- _({len(report['findings']) - 25} more finding(s) in `science-lab-report.json`)_"
            )
        lines.append("")
    else:
        lines.append("All checked biomedical, structural, chemical, and Zenodo RDM artifacts passed.")
        lines.append("")
    return "\n".join(lines)


def _parse_pillars(raw: str) -> list[str]:
    if raw.strip().lower() == "all":
        return list(PILLARS)
    chosen: list[str] = []
    for part in raw.split(","):
        tok = part.strip().lower()
        if not tok:
            continue
        if tok not in PILLARS:
            raise ValueError(
                f"unknown pillar '{tok}' (choose 'all' or comma-separated from {', '.join(PILLARS)})"
            )
        if tok not in chosen:
            chosen.append(tok)
    if not chosen:
        raise ValueError("at least one pillar must be selected")
    return chosen


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="science_lab_verify.py",
        description="Verify Genomics, Structural Biology, Chemistry, and Zenodo RDM research artifacts.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository directory or single artifact file to verify (default: .)",
    )
    parser.add_argument(
        "--require-citation",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if neither CITATION.cff nor zenodo*.json exists in --root",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Write full structured JSON verification report to this file path",
    )
    parser.add_argument(
        "--markdown-summary",
        default="",
        help="Append Markdown summary table to this path (e.g. $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "none"),
        default="medium",
        help="Minimum finding severity that exits with code 1 (default: medium)",
    )
    parser.add_argument(
        "--pillars",
        default="all",
        help="Comma-separated pillars to run or 'all' (default: all)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        sys.stderr.write(f"error: --root path does not exist: {root}\n")
        return 2

    try:
        selected_pillars = _parse_pillars(args.pillars)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    report = scan_repository(
        root,
        require_citation=bool(args.require_citation),
        pillars=selected_pillars,
    )
    report["fail_on"] = args.fail_on
    report["passed"] = not should_fail(report, args.fail_on)

    output_path = args.output.strip() or None
    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md_path = args.markdown_summary.strip() or None
    if md_path:
        md_file = Path(md_path)
        md_file.parent.mkdir(parents=True, exist_ok=True)
        with md_file.open("a", encoding="utf-8") as fh:
            fh.write(format_markdown_summary(report, args.fail_on) + "\n")

    sys.stdout.write(format_stdout_summary(report, args.fail_on, output_path))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
