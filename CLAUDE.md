# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

BrainSAIT reusable GitHub Actions workflow library (`Fadil369/B.I.Lab`). No app code or build system. Docs are bilingual EN/AR, no emojis, guesses marked `[guess]`.

## Layout
- `.github/workflows/`: 17 reusable workflows (`on: workflow_call`) plus 5 repo-internal files that are not callable (`library-lint.yml`, `phi-scan-tests.yml`, `bpr-verify-tests.yml`, `healthcare-security-selftest.yml`, `release-tag-sync.yml`).
- `examples/`: caller workflows, linted in CI.
- `script/phi-scan/`: stdlib-only PHI heuristic scanner and its tests.
- `projects/`: git submodules, pointers only.

## Commands
- Lint workflows (same as CI): `actionlint -color .github/workflows/*.yml examples/*.yml` (CI uses v1.7.7)
- Static workflow security checks (CI runs this too): `python3 script/lint_workflows.py` (fails on `${{ }}` inside `run:` blocks and on non-SHA-pinned third-party actions)
- bpr-verify tests: `python -m unittest -v script/bpr-verify/test_bpr_verify.py`
- phi-scan tests: `python -m unittest discover -s script/phi-scan -v` and `cd script/phi-scan && python -m doctest -v phi_scan.py`
- Self-scan, must stay clean: `python script/phi-scan/phi_scan.py --root . --fail-on medium` (exit 1 = findings, 2 = usage error). Suppress a line inline with `phi-scan:ignore`.

- Run every CI check locally (use this when hosted Actions is unavailable): `script/ci-local.sh`. Enable it as a pre-push gate with `pre-commit install --hook-type pre-push`.

## Workflow conventions
- Pin every third-party action to a full commit SHA with the version as a trailing comment: `uses: actions/checkout@<sha> # v7.0.1`. Never use a tag or branch. This is mandatory for security tools (trivy, codeql, gitleaks), which run with `security-events: write`.
- Top-level `permissions: contents: read`; grant extra permissions per job only.
- Checkout with `persist-credentials: false`.
- Start each reusable workflow with the header comment `# BrainSAIT reusable workflow: ...`. Inputs are typed, kebab-case and have defaults; an empty-string input skips a stage. Secrets are passed explicitly, never `secrets: inherit`.
- When you add or change a workflow, also update the README workflow table, the relevant `examples/` caller, and the header comment.
- Workflow changes affect every BrainSAIT repo (CODEOWNERS: `@Fadil369`).

## Gotchas
- Callers consume this library as `@v1`, a floating major tag that already exists. Nested calls inside `healthcare-security-scan.yml` use `@v1`, so a change to a nested workflow only takes effect for them once `v1` is moved. `release-tag-sync.yml` moves `v1` when a semver tag (`vX.Y.Z`) is pushed; do not move or delete tags yourself without asking.
- Never put PHI, secrets or client names in this repo, logs, artifacts or fixtures. `fhir-validate` and phi-scan tests use synthetic data only.
- `projects/` holds only public Fadil369 repos as submodules. Do not edit files inside them. Bump with `git submodule update --remote projects/<name>` and commit the pointer. After a fresh clone run `git submodule update --init --recursive`.
- `.private/` is local-only (excluded via `.git/info/exclude`) and lists private/client repos. Do not read, commit or reference it.
- `git worktree list` shows worktrees under `~/.gemini/antigravity/worktrees/`. They belong to another tool; do not remove or modify them.
