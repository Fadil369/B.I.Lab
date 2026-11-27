# Healthcare security scan

A reusable GitHub Actions workflow for repositories that handle health data. It runs secret
scanning, dependency and container scanning, CodeQL, and a heuristic check for possible PHI
(protected health information) in code, fixtures and log statements.

> **Read this first.** Passing these checks is evidence of good engineering hygiene. It is not
> proof of HIPAA compliance, PDPL compliance or NPHIES conformance. Compliance depends on
> policies, access controls, hosting, contracts (BAAs / data processing agreements), training
> and audits that no CI pipeline can see. Statements marked **[guess]** below are my
> interpretation and have not been checked against an authoritative source.

**ملخص بالعربية:** سير عمل قابل لإعادة الاستخدام لمستودعات الرعاية الصحية، يفحص الأسرار
المسربة (gitleaks)، والثغرات في الحزم والحاويات وإعدادات البنية (Trivy)، والشيفرة (CodeQL)،
ويبحث عن بيانات صحية محتملة مثل رقم الهوية الوطنية أو الإقامة ورقم الملف الطبي وتاريخ الميلاد
وتسجيلها في السجلات (phi-scan). النتائج أداة مراجعة، ولا تعني بحد ذاتها الامتثال لـ HIPAA أو
نظام حماية البيانات الشخصية أو متطلبات نفيس.

---

## Quick start

Add `.github/workflows/security.yml` to the repository you want to scan:

```yaml
name: Healthcare Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 3 * * 1'   # weekly, to catch newly published CVEs

permissions:
  contents: read

jobs:
  healthcare:
    uses: Fadil369/B.I.Lab/.github/workflows/healthcare-security-scan.yml@v1  # or a SHA
    permissions:
      contents: read
      security-events: write
      actions: read
      packages: read
    with:
      codeql-languages: '["javascript-typescript","python","actions"]'
      dockerfile: Dockerfile          # optional: build and scan the image
      phi-fail-on: medium
    secrets:
      tools-token: ${{ secrets.BILAB_READ_TOKEN }}  # only while B.I.Lab is private
```

The same file is in [`examples/healthcare-security.yml`](../examples/healthcare-security.yml).

Then, in branch protection, require the single check **Healthcare security gate**.

### Things the calling repository must have

| Need | Why |
|---|---|
| `security-events: write`, `actions: read`, `packages: read` | Upload SARIF, and let the nested `trivy-scan.yml` / `codeql.yml` run. A called workflow can't get more than the caller grants. |
| GitHub Advanced Security (private repos) | CodeQL and SARIF upload on private repos need it. Without it set `run-codeql: false` and `upload-sarif: false`; reports are still kept as workflow artifacts. |
| Read access to `Fadil369/B.I.Lab` | The PHI job checks out `script/phi-scan` from here. While this repo is private, pass a fine-grained token with *Contents: read* on this repo as `tools-token`, and allow access under *Settings → Actions → General → Access*. |

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `run-secrets`, `run-dependencies`, `run-codeql`, `run-phi` | `true` | Turn individual checks off. |
| `secrets-full-history` | `true` | On push/schedule scan all history; PRs always scan only their own commits. |
| `trivy-severity` | `CRITICAL,HIGH` | Severities that fail the build. All severities still go to SARIF. |
| `trivy-ignore-unfixed` | `true` | Don't fail on CVEs with no fix available. |
| `image-ref` | `''` | Existing image to scan, via `trivy-scan.yml`. |
| `registry-username` + secret `registry-password` | `''` | Credentials for a private registry holding `image-ref`. |
| `dockerfile`, `docker-context` | `''`, `.` | Build an image locally and scan it. |
| `codeql-languages` | `["actions"]` | JSON array. Only list languages that exist in the repo, or CodeQL fails. |
| `codeql-queries` | `security-extended` | Or `security-and-quality`. |
| `codeql-build-mode` | `none` | `autobuild` for Go and Swift. |
| `phi-fail-on` | `medium` | `low`, `medium`, `high` or `none`. |
| `phi-config` | `.phi-scan.json` | Path to the PHI scanner config in the calling repo. |
| `upload-sarif` | `true` | Send results to code scanning. |
| `artifact-retention-days` | `90` | How long raw gitleaks, built-image and phi-scan reports stay as artifacts (`trivy-scan.yml` keeps its own for 30 days). |
| `tools-ref` | `v1` | Ref of this repo to load phi-scan from. Pin it to a tag or SHA. |

---

## What each check covers, and what it cannot guarantee

### 1. Secrets: gitleaks

| Covers | Cannot guarantee |
|---|---|
| ~150 built-in patterns for cloud keys, tokens, private keys and high-entropy strings, across git history (full on push/schedule, PR commits on PRs). Findings are redacted in output. Custom rules can be added in a `.gitleaks.toml` in the calling repo. | Secrets in formats it has no rule for, including any NPHIES- or vendor-specific credential format **[guess: no public NPHIES token format is known to me]**. Secrets outside git (CI variables, wikis, chat). Secrets that were committed and later force-pushed away still exist in forks and clones. A finding means *rotate the secret first*; rewriting history alone does not make it safe. |

Notes: gitleaks is downloaded from its GitHub release and its SHA-256 is checked, so no
third-party action runs here. GitHub's own *push protection* is stronger for supported
partner tokens and should be turned on as well where available.

### 2. Dependencies and infrastructure: Trivy filesystem scan

Runs the library's [`trivy-scan.yml`](../.github/workflows/trivy-scan.yml) with `scanners: vuln,misconfig`.

| Covers | Cannot guarantee |
|---|---|
| Known CVEs in lockfiles/manifests (npm, pip, Poetry, Go, Maven, Cargo, Composer, etc.) and misconfigurations in Dockerfiles, Kubernetes manifests, Terraform, CloudFormation and Helm. | Vulnerabilities not yet in public advisory databases, flaws in your own code, packages installed at runtime without a lockfile, and whether a vulnerable function is actually reachable. Misconfig checks are generic; they don't know your HIPAA hosting requirements (e.g. that a bucket must be KMS-encrypted with a specific key). |

### 3. Container image: Trivy image scan (optional)

With `image-ref`, this calls `trivy-scan.yml` in image mode. With `dockerfile`, it builds the
image on the runner and scans it in the same job, because a local image can't be passed to
another workflow.

| Covers | Cannot guarantee |
|---|---|
| OS packages and language packages inside the built image, secrets baked into image layers, and image misconfiguration. | The image that actually runs in production (scan the deployed digest too, or add registry scanning), runtime behaviour, or host/cluster hardening. |

### 4. Code: CodeQL

Runs the library's [`codeql.yml`](../.github/workflows/codeql.yml).

| Covers | Cannot guarantee |
|---|---|
| Data-flow analysis for injection, XSS, path traversal, SSRF, unsafe deserialization, weak crypto, hard-coded credentials and, with `actions`, insecure workflow patterns. `security-extended` adds lower-precision queries. | Business-logic and authorization flaws (e.g. a clinician seeing another facility's patients), missing audit logging, missing encryption of PHI at rest, consent handling. Compiled languages use `autobuild`; repos with custom builds should call CodeQL directly. |

### 5. Possible PHI: phi-scan

`script/phi-scan/phi_scan.py` is a small, dependency-free Python scanner written for this
workflow. It prints and uploads **masked** values only (e.g. `10******53`), so the scan never
copies PHI into CI logs or the Security tab.

| Rule | Looks for | Default severity |
|---|---|---|
| PHI001 | 10-digit number starting 1 or 2 that passes Luhn, next to an identity keyword (national ID, Iqama, هوية, الإقامة…) | high |
| PHI002 | Same number shape without an identity keyword and not next to time/size words | low (medium near patient words) |
| PHI003 | US SSN format, excluding invalid ranges and well-known examples | high |
| PHI004 | Saudi mobile numbers (05…, +9665…) | low, medium near patient words |
| PHI005 | Email addresses outside example.com/.org/.net, test, invalid, GitHub noreply | low, medium near patient words |
| PHI006 | MRN / patient ID / file number assigned a literal containing digits | high |
| PHI007 | Date of birth (Gregorian or Hijri) assigned a literal | medium |
| PHI008 | Log/print calls (including Kotlin/Android `Log.d/i/w/e/v/wtf` and `Timber.*`) whose arguments mention patient, national ID, MRN, DOB, phone, email, address, IBAN, SCFHS license or NPHIES identifiers… | medium |
| PHI009 | FHIR `Patient` resources with identifier/name/birthDate/telecom/address outside a synthetic path | medium |
| PHI010 | HL7 v2 messages with a PID segment, DICOM/NIfTI/C-CDA files | high |
| PHI011 | Saudi bank account IBAN (`SA` followed by 22 digits, excluding `SA0000000000000000000000`) | high |

"Patient words" include English and Arabic terms (patient, MRN, DOB, diagnosis, NPHIES,
claim, مريض، تاريخ الميلاد…), matched within 80 characters of the value.

| Covers | Cannot guarantee |
|---|---|
| Common shapes of identifiers that end up in fixtures, seed scripts, docs and logs, plus logging calls that are likely to write PHI. | **Absence of PHI.** It does not detect names, free-text clinical notes, addresses, diagnoses on their own, photos, scanned documents, PDFs, spreadsheets, or anything in binary files, databases, object storage or production logs. It cannot tell real data from realistic synthetic data; a human has to confirm. It cannot check runtime behaviour, only source text. The Saudi ID check digit is assumed to be Luhn **[guess: widely documented, not verified against an official NIC specification]**. |

**Generated files.** JS/CSS files whose average line is longer than 500 characters are treated
as minified bundles and skipped (the count is printed). Their sources should be scanned
instead. If you commit bundles that embed data, scan the data source.

#### Suppressing a finding

Inline, on the same line or the line above, always with a reason:

```python
national_id = "1000000008"  # phi-scan:ignore synthetic test vector
```

Or in `.phi-scan.json` at the repo root:

```json
{
  "exclude_paths": ["tests/fixtures/legacy/**"],
  "synthetic_paths": ["seed/demo/**"],
  "allow_values": ["0551234567"],
  "disabled_rules": ["PHI005"]
}
```

`synthetic_paths` lowers HL7 findings and silences PHI009 for paths you have declared
synthetic. Suppressions are listed in every run so they can be reviewed.

#### How noisy is it?

Measured on 2026-11-27 with the default `medium` threshold:

| Repository | Files scanned | Failing (medium+) | Low (info) | Notes |
|---|---|---|---|---|
| Fadil369/B.I.Lab | 511 | 0 | 5 | Low hits are vendor support emails in starter workflows. |
| Fadil369/fadil369.github.io | 1,255 (789 bundles skipped) | 12 | 71 | All 12 are in demo data, tests or UI copy: DOBs in `nphiesDemo.ts`, phone numbers in tests and the BPR Nvidia page, one email in `IntakeForm.tsx`, one log line naming `mobile`. Each needs a human to confirm it is synthetic, then an inline ignore. |

---

## How this lines up with HIPAA and Saudi requirements

**[guess]** This mapping is my reading of the rules, not legal advice. Have your compliance
officer confirm it.

| Requirement | How the scan helps | What else is needed |
|---|---|---|
| HIPAA 45 CFR 164.308(a)(1)(ii)(A)-(B), risk analysis and risk management | Produces a repeatable, dated record of technical findings per commit. | A documented risk analysis that covers people, processes and infrastructure. |
| HIPAA 164.308(a)(5)(ii)(B), protection from malicious software | Dependency and image CVE scanning. | Endpoint and runtime protection. |
| HIPAA 164.312(a)(1), access control; 164.312(e)(1), transmission security | CodeQL and Trivy misconfig catch some hard-coded credentials and insecure configs. | Real RBAC, MFA, TLS everywhere, key management. |
| HIPAA 164.312(b), audit controls | PHI008 flags PHI going to *application* logs. | An actual audit log of who accessed which record, retained per policy (HIPAA documentation retention is 6 years, far longer than artifact retention). |
| HIPAA 164.514(b), de-identification (Safe Harbor) | phi-scan looks for a few of the 18 identifiers in code. | Proper de-identification of any dataset used for test or analytics. |
| Proposed HIPAA Security Rule update (NPRM published Jan 2025) | Would make periodic vulnerability scanning explicit. **[guess: I don't know whether a final rule has been issued as of today; check before relying on it]** | Penetration tests, asset inventory, network map, as the final rule requires. |
| Saudi PDPL (SDAIA) | Helps keep personal and health data out of source control. | Lawful basis, data residency, breach notification, DPO duties. **[guess on scope as applied to dev pipelines]** |
| NCA Essential Cybersecurity Controls (ECC) | Supports secure development and vulnerability management controls. **[guess: exact ECC control numbers not checked]** | The rest of the ECC/CCC control set. |
| NPHIES (CCHI) | Keeps NPHIES credentials, payer/member IDs and claim payloads out of git; flags FHIR Patient fixtures. | Conformance to the NPHIES FHIR implementation guide and its onboarding and certificate requirements. **[guess: I am not aware of a published NPHIES requirement for CI scanning; this aligns with general expectations, not a specific NPHIES rule]** |

---

## Operating notes

- **Pin everything.** Third-party actions in this workflow, `trivy-scan.yml` and `codeql.yml`
  are pinned to commit SHAs, because a hijacked tag on a scanner would run with
  `security-events: write`. Pin `tools-ref` and the caller's `uses:` line to `@v1` or a commit SHA.
- **Weekly schedule.** New CVEs appear without code changes; the scheduled run catches them.
- **Triage SLA [guess, adjust to your policy]:** secrets and high PHI findings same day;
  critical CVEs within 7 days; high within 30.
- **If real PHI is found:** treat it as a possible breach. Remove it, purge it from history
  (`git filter-repo`), invalidate forks/caches where possible, and follow your incident and
  breach-notification process. A green rerun does not undo the exposure.
- **Workflow artifacts** keep masked reports for `artifact-retention-days`. They are not an
  audit log and should not be treated as one.

## Known gaps and possible next steps

- No detection of names or free-text clinical notes. An NER-based check (e.g. Microsoft
  Presidio) could be added as an optional job, at the cost of speed and false positives.
- No custom gitleaks rules for NPHIES or HIS vendor credentials yet.
- No SBOM output. Trivy can emit CycloneDX/SPDX if procurement or auditors ask for it.
- No runtime or DAST testing (e.g. OWASP ZAP against a staging environment).
- No license compliance check.

## Files

| Path | Purpose |
|---|---|
| `.github/workflows/healthcare-security-scan.yml` | The reusable workflow. |
| `.github/workflows/trivy-scan.yml`, `codeql.yml` | Library workflows it calls (SHA-pinned, `upload-sarif` input added). |
| `examples/healthcare-security.yml` | Copy-ready caller. |
| `.github/workflows/healthcare-security-selftest.yml` | Manual end-to-end run against this repo (internal). |
| `.github/workflows/phi-scan-tests.yml` | Unit tests and self-scan for phi-scan (internal). |
| `script/phi-scan/phi_scan.py` | The PHI heuristics scanner. |
| `script/phi-scan/test_phi_scan.py` | Tests (all identifiers synthetic, generated at runtime). |
| `.phi-scan.json` | This repo's scanner config (excludes the test file). |
