# B.I.Lab: BrainSAIT reusable workflow library

مكتبة سير عمل GitHub Actions القابلة لإعادة الاستخدام لمشاريع BrainSAIT

Shared GitHub Actions workflows for BrainSAIT repositories. Each file in
[`.github/workflows/`](.github/workflows) is a **reusable workflow** (`on: workflow_call`),
so a product repo calls it in a few lines instead of copying CI logic around.

## Workflows

| Workflow | What it does | Key inputs |
| --- | --- | --- |
| [`node-ci.yml`](.github/workflows/node-ci.yml) | Install, lint, type-check, test, build a Node / TypeScript project (Next.js, React, Workers code) | `node-version`, `package-manager` (npm/pnpm/yarn), `working-directory`, script names |
| [`node-site.yml`](.github/workflows/node-site.yml) | Site quality gate: install, caller-supplied commands, optional PHP stage and Playwright Chromium stage, npm audit | `pre-browser-commands`, `php-version`, `php-extensions`, `php-commands`, `browser-commands`, `audit-level` |
| [`python-ci.yml`](.github/workflows/python-ci.yml) | Ruff lint + format check, mypy, pytest with coverage for Python / FastAPI services | `python-version`, `install-command`, `mypy-target`, `pytest-args` |
| [`docker-build.yml`](.github/workflows/docker-build.yml) | hadolint, Buildx build with GHA cache, push to `ghcr.io` (never on PRs), SBOM + provenance attestation | `image-name`, `context`, `dockerfile`, `platforms`, `push` |
| [`cloudflare-workers-deploy.yml`](.github/workflows/cloudflare-workers-deploy.yml) | Test then `wrangler deploy` to a Wrangler environment, behind a GitHub Environment | `working-directory`, `environment`, `dry-run`; secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` |
| [`cloudflare-pages-deploy.yml`](.github/workflows/cloudflare-pages-deploy.yml) | Build and `wrangler pages deploy`; PRs get a preview on their branch alias | `project-name`, `output-directory`, `build-command` |
| [`github-pages-deploy.yml`](.github/workflows/github-pages-deploy.yml) | Optional build, then publish a folder to GitHub Pages | `path`, `build-command` |
| [`claude-code.yml`](.github/workflows/claude-code.yml) | Claude Code: answers `@claude` mentions, or reviews PRs with the code-review plugin | `mode` (mention/review); secret `CLAUDE_CODE_OAUTH_TOKEN` |
| [`codeql.yml`](.github/workflows/codeql.yml) | CodeQL analysis per language, results in the Security tab | `languages` (JSON array), `queries`, `build-mode`, `upload-sarif` |
| [`trivy-scan.yml`](.github/workflows/trivy-scan.yml) | Trivy vuln / secret / misconfig scan of the repo or an image, SARIF to the Security tab | `scan-type` (fs/image/config), `scan-ref`, `severity`, `fail-on-findings`, `upload-sarif` |
| [`healthcare-security-scan.yml`](.github/workflows/healthcare-security-scan.yml) | HIPAA/NPHIES-oriented bundle: gitleaks history scan, Trivy (repo + image), CodeQL, and `phi-scan` for possible PHI (Saudi ID/Iqama, MRN, DOB, FHIR Patient, HL7, PHI in log calls), behind one gate check. [Coverage and limits](docs/healthcare-security-scan.md) | `codeql-languages`, `image-ref` / `dockerfile`, `phi-fail-on`, `upload-sarif`; secret `tools-token` |
| [`dependency-review.yml`](.github/workflows/dependency-review.yml) | Blocks PRs that add vulnerable or copyleft-licensed dependencies | `fail-on-severity`, `deny-licenses` |
| [`fhir-validate.yml`](.github/workflows/fhir-validate.yml) | **Experimental.** HL7 FHIR R4 validator over test fixtures, optional IGs (e.g. NPHIES packages) | `path`, `fhir-version`, `implementation-guides` |
| [`android-ci.yml`](.github/workflows/android-ci.yml) | Gradle CI for Kotlin / Jetpack Compose multi-module Android apps: unit tests, lint, debug APK assembly; reports and APKs uploaded as artifacts | `java-version`, `working-directory`, `gradle-test-tasks`, `gradle-lint-tasks`, `gradle-assemble-tasks`, `artifact-suffix` |
| [`android-release.yml`](.github/workflows/android-release.yml) | Release APK build with optional keystore signing, build provenance attestation, GitHub Release, and optional dispatch of release metadata to an ecosystem hub repo | `modules`, `gradle-release-tasks`, `suite-name`, `create-release`, `dispatch-repo`; keystore and `DISPATCH_TOKEN` secrets |
| [`bpr-trust-fhir-verify.yml`](.github/workflows/bpr-trust-fhir-verify.yml) | BPR X.509 PKI trust check (chain, expiry horizon) plus synthetic FHIR R4 / NPHIES and trust-governance verification via `script/bpr-verify` | `trust-dir`, `fhir-paths`, `min-days`, `require-trust`, `require-fhir`, `tools-ref`, `artifact-suffix` |

`library-lint.yml`, `phi-scan-tests.yml`, `bpr-verify-tests.yml` and `healthcare-security-selftest.yml` are this repo's own CI, and `release-tag-sync.yml` moves the floating `v1` tag when a `vX.Y.Z` tag is pushed. They are not meant to be called.

## Usage

```yaml
# .github/workflows/ci.yml in a product repo
name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    uses: Fadil369/B.I.Lab/.github/workflows/python-ci.yml@v1
    with:
      python-version: "3.12"
```

Ready-to-copy callers live in [`examples/`](examples):

- [`fastapi-service.yml`](examples/fastapi-service.yml): Python CI, then Docker build to GHCR, then Trivy image scan
- [`cloudflare-worker.yml`](examples/cloudflare-worker.yml): Node CI, then Wrangler deploy (dry run on PRs)
- [`github-pages-site.yml`](examples/github-pages-site.yml): static site such as `fadil369.github.io`
- [`static-site.yml`](examples/static-site.yml): site quality gate + CodeQL + Claude mention/review, as used by `fadil369.github.io`
- [`security.yml`](examples/security.yml): CodeQL + Trivy + dependency review for any repo
- [`healthcare-security.yml`](examples/healthcare-security.yml): the healthcare bundle (secrets, dependencies, image, CodeQL, possible PHI) for repos that touch patient or claims data
- [`fhir-fixtures.yml`](examples/fhir-fixtures.yml): FHIR validation of example resources

### Notes for callers

- **Permissions.** A reusable workflow can never get more permissions than the calling job grants.
  Jobs that push images, upload SARIF or deploy Pages must pass the `permissions:` block shown in the examples.
- **Secrets.** Pass secrets explicitly (as in the examples) rather than `secrets: inherit`, so each workflow only sees what it needs.
- **Versioning.** Call `@v1` (a tag on this repo) rather than `@main`, so a change here does not break every repo at once.
  Pin to a commit SHA for production deploys of regulated services.
- **Pinned actions.** Every third-party action inside these workflows is pinned to a commit SHA (with its version in a comment) and runs on Node 24. Dependabot proposes the bumps.
- **Private repo access.** If this repository is private, enable
  *Settings → Actions → General → Access → "Accessible from repositories owned by the user"* so other repos can call it.

## Projects

Public BrainSAIT projects are indexed in [`projects/`](projects/README.md) as git submodules.

## Compliance guardrails (HIPAA / NPHIES)

These workflows are CI/CD plumbing; they do not make an app compliant on their own. They do help:

- Every workflow defaults to `permissions: contents: read` and asks for more only per job.
- Images ship with SBOM and build provenance, and Trivy checks for leaked secrets and misconfigurations.
- Deploys run behind GitHub Environments, so production can require approval and keep an audit trail of who deployed what.
- **Never put PHI in a repository, workflow log, artifact or test fixture.** `fhir-validate.yml` is for synthetic data only.
- [`healthcare-security-scan.yml`](.github/workflows/healthcare-security-scan.yml) adds secret-history scanning and a heuristic check for possible PHI. Read [what it covers and cannot guarantee](docs/healthcare-security-scan.md) before relying on it.
- Security tooling (`trivy-scan.yml`, `codeql.yml`, the healthcare scan) pins third-party actions to commit SHAs, because a hijacked tag on a scanner runs with `security-events: write`.

## Origin

This repo started as a copy of [actions/starter-workflows](https://github.com/actions/starter-workflows) (MIT, see [LICENSE](LICENSE)).
The original templates were removed and replaced with the BrainSAIT reusable set above.

## Maintainer and citation

Maintained by Mohamed Elfadil ([ORCID 0009-0003-7485-3575](https://orcid.org/0009-0003-7485-3575)). Citation metadata is in [`CITATION.cff`](CITATION.cff); GitHub shows it as "Cite this repository".
