"""Unit tests for script/guard_workflows.py (stdlib only, synthetic fixtures)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import guard_workflows as gw  # noqa: E402

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

CLEAN = f"""# BrainSAIT reusable workflow: synthetic example
name: demo
on:
  workflow_call:
    inputs:
      node-version:
        type: string
        default: "24"
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
        with:
          persist-credentials: false
      - name: Echo
        run: echo ok
"""


def errors_for(text: str, name: str = "demo.yml") -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_text(text)
        return gw.check_file(path)


class GuardWorkflowsTest(unittest.TestCase):
    def test_clean_fixture_passes(self) -> None:
        self.assertEqual(errors_for(CLEAN), [])

    def test_missing_header(self) -> None:
        text = CLEAN.replace("# BrainSAIT reusable workflow: synthetic example\n", "")
        self.assertTrue(any("header comment" in e for e in errors_for(text)))

    def test_tag_pin(self) -> None:
        text = CLEAN.replace(f"actions/checkout@{SHA} # v7.0.1", "actions/checkout@v4")
        self.assertTrue(any("not SHA-pinned" in e for e in errors_for(text)))

    def test_missing_version_comment(self) -> None:
        text = CLEAN.replace(" # v7.0.1", "")
        self.assertTrue(any("version comment" in e for e in errors_for(text)))

    def test_extra_top_level_permission(self) -> None:
        text = CLEAN.replace("  contents: read\n", "  contents: write\n")
        self.assertTrue(any("permissions.contents" in e for e in errors_for(text)))

    def test_checkout_without_persist_credentials(self) -> None:
        text = CLEAN.replace("        with:\n          persist-credentials: false\n", "")
        self.assertTrue(any("persist-credentials" in e for e in errors_for(text)))

    def test_checkout_with_uses_after_with_order(self) -> None:
        text = CLEAN.replace(
            f"      - uses: actions/checkout@{SHA} # v7.0.1\n        with:\n          persist-credentials: false\n",
            f"      - name: Checkout\n        with:\n          persist-credentials: false\n        uses: actions/checkout@{SHA} # v7.0.1\n",
        )
        self.assertEqual(errors_for(text), [])

    def test_persist_credentials_exemption(self) -> None:
        text = CLEAN.replace("        with:\n          persist-credentials: false\n", "")
        self.assertEqual(errors_for(text, "release-tag-sync.yml"), [])

    def test_secrets_inherit(self) -> None:
        text = CLEAN + "  call:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n"
        self.assertTrue(any("secrets: inherit" in e for e in errors_for(text)))

    def test_input_not_kebab_case(self) -> None:
        text = CLEAN.replace("node-version:", "node_version:")
        self.assertTrue(any("kebab-case" in e for e in errors_for(text)))

    def test_input_missing_type_and_default(self) -> None:
        text = CLEAN.replace('        type: string\n        default: "24"\n', "        description: x\n")
        errs = errors_for(text)
        self.assertTrue(any("missing required 'type'" in e for e in errs))
        self.assertTrue(any("missing required 'default'" in e for e in errs))

    def test_required_input_may_omit_default(self) -> None:
        text = CLEAN.replace('        default: "24"\n', "        required: true\n")
        self.assertEqual(errors_for(text), [])

    def test_internal_and_local_refs_allowed(self) -> None:
        text = CLEAN + (
            "  a:\n    uses: Fadil369/B.I.Lab/.github/workflows/x.yml@v1\n"
            "  b:\n    uses: ./.github/workflows/y.yml\n"
        )
        self.assertEqual(errors_for(text), [])

    def test_non_reusable_skips_reusable_only_checks(self) -> None:
        text = CLEAN.replace("workflow_call:", "push:").replace(
            "# BrainSAIT reusable workflow: synthetic example\n", ""
        )
        self.assertEqual(errors_for(text), [])

    def test_fix_uses_line_skips_pinned_and_internal(self) -> None:
        self.assertIsNone(gw.fix_uses_line(f"      - uses: actions/checkout@{SHA} # v7.0.1"))
        self.assertIsNone(gw.fix_uses_line("    uses: Fadil369/B.I.Lab/.github/workflows/x.yml@v1"))
        self.assertIsNone(gw.fix_uses_line("    uses: ./.github/workflows/x.yml"))

    def test_resolve_skips_without_network(self) -> None:
        self.assertTrue(gw.resolve_tag_to_sha(f"actions/checkout@{SHA}").startswith("SKIP"))
        self.assertTrue(gw.resolve_tag_to_sha("./local@v1").startswith("SKIP"))

    def test_detect_tag_uses_flags_tags_only(self) -> None:
        text = (
            "# BrainSAIT reusable workflow: synthetic example\n"
            "name: demo\non:\n  workflow_call:\n    inputs:\n      node-version:\n        type: string\n        default: \"24\"\n"
            "permissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: actions/checkout@{SHA} # v7.0.1\n"  # pinned -> skipped
            "      - uses: actions/setup-node@v4\n"            # tag -> flagged
            "      - uses: ./.github/workflows/x.yml\n"           # local -> skipped
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.yml"
            path.write_text(text)
            hits = gw.detect_tag_uses(path)
        self.assertEqual(len(hits), 1)
        self.assertIn("actions/setup-node@v4", hits[0][1])

    def test_detect_tag_uses_clean_is_empty(self) -> None:
        text = (
            "# BrainSAIT reusable workflow: synthetic example\n"
            "name: demo\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.yml"
            path.write_text(text)
            self.assertEqual(gw.detect_tag_uses(path), [])


if __name__ == "__main__":
    unittest.main()
