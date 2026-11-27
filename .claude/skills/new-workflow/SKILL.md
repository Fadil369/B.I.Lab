---
name: new-workflow
description: Scaffold a new BrainSAIT reusable workflow following this repo's conventions, with README table entry and example caller.
disable-model-invocation: true
---

Create a new reusable workflow named `$ARGUMENTS` (kebab-case; ask for a one-line purpose if none is given).

1. Read one similar existing file in `.github/workflows/` (e.g. `node-ci.yml`) and mirror its structure.
2. Write `.github/workflows/<name>.yml`:
   - Header comment `# BrainSAIT reusable workflow: <purpose>`.
   - `on: workflow_call` with typed kebab-case inputs that have defaults; empty-string inputs skip a stage. Secrets declared explicitly, never `secrets: inherit`.
   - Top-level `permissions: contents: read`; extra permissions per job only.
   - `actions/checkout` with `persist-credentials: false`.
   - Every third-party action pinned to a full commit SHA with a trailing `# vX.Y.Z` comment. Reuse SHAs already present in the repo where the action is the same; look up new ones with `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`.
3. Add a row to the workflow table in `README.md`.
4. If a caller makes sense, add `examples/<name>.yml` using `uses: Fadil369/B.I.Lab/.github/workflows/<name>.yml@v1`. Nested calls between library workflows stay on `@main` (no `v1` tag exists yet).
5. Run `actionlint .github/workflows/<name>.yml examples/*.yml` if installed, and `python script/phi-scan/phi_scan.py --root . --fail-on medium`. Report anything that fails.

Never include PHI, secrets or client names in any file.
