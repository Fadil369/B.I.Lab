#!/usr/bin/env bash
# Run the same checks as the repo's CI workflows (library-lint, phi-scan-tests, bpr-verify tests)
# on this machine. Use it when hosted GitHub Actions is unavailable, and as a pre-push gate.
# Usage: script/ci-local.sh        (exit 0 = all checks passed)
set -u
cd "$(git rev-parse --show-toplevel)"

fail=0
run() {
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  if "$@"; then printf 'PASS: %s\n' "$name"; else printf 'FAIL: %s\n' "$name"; fail=1; fi
}

if command -v actionlint >/dev/null 2>&1; then
  run "actionlint" actionlint -color .github/workflows/*.yml examples/*.yml
else
  printf '\nSKIP: actionlint not installed (brew install actionlint)\n'; fail=1
fi
run "workflow security checks" python3 script/lint_workflows.py
run "bpr-verify unit tests" python3 -m unittest -v script/bpr-verify/test_bpr_verify.py
run "phi-scan unit tests" python3 -m unittest discover -s script/phi-scan -v
run "phi-scan doctests" bash -c 'cd script/phi-scan && python3 -m doctest phi_scan.py'
run "phi-scan self-scan" python3 script/phi-scan/phi_scan.py --root . --fail-on medium

printf '\n'
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
