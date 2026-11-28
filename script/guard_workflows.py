#!/usr/bin/env python3
"""BrainSAIT workflow guardrail: enforce every CLAUDE.md convention + resolve dependabot tag->SHA.

Zero dependencies (stdlib only), mirroring the repo's stdlib-only ``script/phi-scan``.

Checks (exit 1 on any violation):
  1. Reusable workflows (on: workflow_call) start with the header comment
     `# BrainSAIT reusable workflow: <one-line summary>`.
  2. Every `uses:` is pinned to a full 40-char commit SHA (or `./...` / internal
     `Fadil369/B.I.Lab/...` / `docker://...@sha256:...`).
  3. Reusable workflows have top-level `permissions: contents: read` only
     (extra perms granted per job).
  4. Every `actions/checkout` uses `persist-credentials: false`
     (except files in PERSIST_CREDENTIALS_EXEMPT).
  5. No `secrets: inherit` anywhere.
  6. Reusable-workflow inputs are typed, kebab-case, and carry a default
     (empty-string input skips a stage;
     an input marked ``required: true`` may omit the default).
  7. SHA-pinned actions carry a trailing version comment `# vX[.Y[.Z]]`.

Guardrail modes (first positional arg):
  check     : validate .github/workflows/*.yml (+ examples/*.yml when --include-examples)
  resolve   : given a dependabot diff (tag-based uses lines), resolve each tag to its
              commit SHA and print a ready-to-apply patch block.
  fix       : auto-remediate -- convert every tag-based ``uses:`` to a SHA pin in place,
              idempotently (already-SHA-pinned and local/internal actions are skipped).
              Use --commit to git commit the remediated files; --include-examples also
              remediates examples/ caller workflows.
              Add --check to only *detect* tag-based uses (exit 1 if any found) without
              modifying files -- the CI-side Dependabot regression detector.

Usage:
  python3 script/guard_workflows.py check [--include-examples] [paths...]
  python3 script/guard_workflows.py resolve <uses-line> [<uses-line> ...]
  python3 script/guard_workflows.py fix [--include-examples] [--commit] [--check] [paths...]

Examples:
  python3 script/guard_workflows.py check
  python3 script/guard_workflows.py resolve "actions/checkout@v7" "docker/setup-qemu-action@v4"
  python3 script/guard_workflows.py fix --commit
  python3 script/guard_workflows.py fix --check --include-examples   # CI: fail on Dependabot tag bumps
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REUSABLE_HEADER_RE = re.compile(r"^# BrainSAIT reusable workflow: .+")
VERSION_COMMENT_RE = re.compile(r"\bv?\d+(?:\.\d+){0,2}\b")
PINNED_ACTION_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
PINNED_DOCKER_RE = re.compile(r"^docker://.+@sha256:[0-9a-f]{64}$")
KEBAB_CASE_RE = re.compile(r"^[a-z][a-z0-9-]*$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
USES_LINE_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")

# Files allowed to leave checkout credentials persisted.
#   release-tag-sync.yml: moves floating major tags with the checkout token.
#   claude-code.yml: [guess] claude-code-action pushes branches/comments using the
#     checkout credentials; setting persist-credentials: false there is untested.
PERSIST_CREDENTIALS_EXEMPT = frozenset({"release-tag-sync.yml", "claude-code.yml"})

INTERNAL_PREFIXES = ("Fadil369/B.I.Lab/",)
LOCAL_PREFIXES = ("./",)


# ---------------------------------------------------------------------------
# Tiny indentation-aware YAML navigator (stdlib only)
# ---------------------------------------------------------------------------

class YamlNode:
    """A node in an indentation-based YAML mapping tree."""

    __slots__ = ("indent", "key", "value", "line", "children")

    def __init__(self, indent: int, key: str, value: str | None, line: int):
        self.indent = indent
        self.key = key
        self.value = value
        self.line = line
        self.children: list[YamlNode] = []

    def find_child(self, key: str) -> "YamlNode | None":
        for c in self.children:
            if c.key == key:
                return c
        return None

    def find_all(self, key: str) -> list["YamlNode"]:
        out: list[YamlNode] = []
        if self.key == key:
            out.append(self)
        for c in self.children:
            out.extend(c.find_all(key))
        return out


def parse_indent_tree(text: str) -> list[YamlNode]:
    """Parse a YAML subset into an indentation tree of YamlNodes.

    Handles block mappings and block sequences (``- key: value``). Comments and
    blank lines are dropped; folded/literal block scalars (``|`` / ``>``) are not
    descended into, which is sufficient for the conventions checked here.
    """
    raw_nodes: list[YamlNode] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = stripped
        if content.startswith("- "):
            content = content[2:].lstrip(" ")
        elif content.startswith("-"):
            content = content[1:].lstrip(" ")
        if ":" in content:
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip() or None
        else:
            key = content
            val = None
        raw_nodes.append(YamlNode(indent, key, val, lineno))

    roots: list[YamlNode] = []
    stack: list[tuple[YamlNode, int]] = []  # (node, indent)
    for node in raw_nodes:
        while stack and stack[-1][1] >= node.indent:
            stack.pop()
        if stack:
            stack[-1][0].children.append(node)
        else:
            roots.append(node)
        stack.append((node, node.indent))
    return roots


def _top(roots: list[YamlNode]) -> YamlNode:
    """Wrap top-level keys in one synthetic document node (indent -1)."""
    doc = YamlNode(-1, "", None, 0)
    doc.children = roots
    return doc


def is_reusable_workflow(roots: list[YamlNode]) -> bool:
    root = _top(roots)
    on = root.find_child("on")
    if on is None:
        return False
    return on.find_child("workflow_call") is not None


# ---------------------------------------------------------------------------
# Convention checks
# ---------------------------------------------------------------------------

def check_header_comment(text: str, path: Path, is_reusable: bool) -> list[str]:
    errors: list[str] = []
    if is_reusable:
        first_lines = text.splitlines()[:3]
        if not any(REUSABLE_HEADER_RE.match(line.strip()) for line in first_lines):
            errors.append(
                f"{path}:1: reusable workflow missing header comment "
                "('# BrainSAIT reusable workflow: ...')"
            )
    return errors


def check_uses_pin(path: Path, roots: list[YamlNode]) -> list[str]:
    errors: list[str] = []
    for node in _all_nodes(roots):
        if node.key != "uses" or not isinstance(node.value, str):
            continue
        value = node.value.strip()
        # Strip trailing version comment so SHA-pin validation sees only the ref.
        pin_value = value.split("#", 1)[0].strip()
        if pin_value.startswith(LOCAL_PREFIXES) or pin_value.startswith(INTERNAL_PREFIXES):
            continue
        if pin_value.startswith("docker://"):
            if not PINNED_DOCKER_RE.match(pin_value):
                errors.append(
                    f"{path}:{node.line}: docker action not digest-pinned '{value}' "
                    "(must be docker://image@sha256:<64 hex>)"
                )
            continue
        if not PINNED_ACTION_RE.match(pin_value):
            errors.append(
                f"{path}:{node.line}: action not SHA-pinned '{value}' "
                "(must be owner/repo@<40-char commit SHA>, e.g. "
                "actions/checkout@3d3c42e... # v7.0.1)"
            )
        elif not _has_version_comment(value):
            errors.append(
                f"{path}:{node.line}: SHA-pinned action missing trailing version comment "
                f"'{value}' (expected '...@<sha> # vX.Y.Z')"
            )
    return errors


def _all_nodes(roots: list[YamlNode]) -> Iterable[YamlNode]:
    for root in roots:
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(node.children)


def check_top_level_permissions(path: Path, roots: list[YamlNode], is_reusable: bool) -> list[str]:
    errors: list[str] = []
    if not is_reusable:
        return errors
    root = _top(roots)
    perms = root.find_child("permissions")
    if perms is None:
        return errors
    contents = perms.find_child("contents")
    if contents is None or contents.value != "read":
        errors.append(
            f"{path}:{perms.line}: top-level permissions.contents must be 'read' "
            "(grant extra permissions per job only)"
        )
    return errors


def check_persist_credentials(path: Path, text: str) -> list[str]:
    """Every actions/checkout step must set ``persist-credentials: false``.

    Text-based so it is independent of key order inside a step (``uses`` may
    precede or follow ``with``).
    """
    errors: list[str] = []
    if path.name in PERSIST_CREDENTIALS_EXEMPT:
        return errors
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        m = USES_LINE_RE.match(line)
        if not m or not m.group(1).startswith("actions/checkout@"):
            continue
        # Find the start of this step: nearest line at or above with a "- " dash.
        start = idx
        while start > 0 and not lines[start].lstrip().startswith("- "):
            start -= 1
        dash_indent = len(lines[start]) - len(lines[start].lstrip(" "))
        end = idx + 1
        while end < len(lines):
            cur = lines[end]
            if cur.strip() and (len(cur) - len(cur.lstrip(" "))) <= dash_indent:
                break
            end += 1
        block = lines[start:end]
        if not any(re.match(r"^\s*persist-credentials:\s*false\b", b) for b in block):
            errors.append(
                f"{path}:{idx + 1}: actions/checkout missing persist-credentials: false "
                "(exemptions: see PERSIST_CREDENTIALS_EXEMPT)"
            )
    return errors


def check_no_secrets_inherit(text: str, path: Path) -> list[str]:
    errors: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if "secrets: inherit" in line:
            errors.append(
                f"{path}:{idx}: 'secrets: inherit' is forbidden; pass secrets explicitly"
            )
    return errors


def _has_version_comment(value: str) -> bool:
    comment = value.split("#", 1)[-1] if "#" in value else ""
    return bool(VERSION_COMMENT_RE.search(comment))


def check_inputs_typed_kebab_defaults(path: Path, roots: list[YamlNode], is_reusable: bool) -> list[str]:
    errors: list[str] = []
    if not is_reusable:
        return errors
    root = _top(roots)
    on = root.find_child("on")
    if on is None:
        return errors
    wc = on.find_child("workflow_call")
    if wc is None:
        return errors
    inputs = wc.find_child("inputs")
    if inputs is None:
        return errors
    for inp in inputs.children:
        name = inp.key
        if not KEBAB_CASE_RE.match(name):
            errors.append(
                f"{path}:{inp.line}: input '{name}' is not kebab-case "
                "(lowercase letters, digits, hyphens; start with a letter)"
            )
        if inp.find_child("type") is None:
            errors.append(
                f"{path}:{inp.line}: input '{name}' missing required 'type'"
            )
        req = inp.find_child("required")
        is_required = req is not None and req.value == "true"
        if inp.find_child("default") is None and not is_required:
            errors.append(
                f"{path}:{inp.line}: input '{name}' missing required 'default'"
            )
    return errors


def check_file(path: Path) -> list[str]:
    text = path.read_text()
    roots = parse_indent_tree(text)
    reusable = is_reusable_workflow(roots)
    errors: list[str] = []
    errors += check_header_comment(text, path, reusable)
    errors += check_uses_pin(path, roots)
    errors += check_top_level_permissions(path, roots, reusable)
    errors += check_persist_credentials(path, text)
    errors += check_no_secrets_inherit(text, path)
    errors += check_inputs_typed_kebab_defaults(path, roots, reusable)
    return errors


# ---------------------------------------------------------------------------
# dependabot tag -> SHA resolver
# ---------------------------------------------------------------------------

def resolve_action_ref(action: str, ref: str) -> str | None:
    """Resolve a tag ref to its commit SHA via ``git ls-remote``.

    Returns the 40-char SHA or ``None`` when the tag cannot be resolved.
    """
    remote = f"https://github.com/{action}.git"
    try:
        out = subprocess.check_output(
            ["git", "ls-remote", remote, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        ).strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    if not out:
        return None
    # Annotated tags list the tag object first and the peeled commit (^{}) last;
    # the commit SHA is what a pin must reference.
    return out.splitlines()[-1].split()[0]


def resolve_tag_to_sha(uses_line: str) -> str:
    """Resolve a tag-based `uses: owner/repo@tag` to `owner/repo@<sha> # tag`."""
    uses_line = uses_line.strip()
    uses_line = re.sub(r"^.*?uses:\s*", "", uses_line)
    if "@" not in uses_line:
        return f"ERROR: no '@' in '{uses_line}'"
    action, ref = uses_line.rsplit("@", 1)
    ref = ref.split("#")[0].strip()
    action = action.strip()

    if action.startswith(LOCAL_PREFIXES) or action.startswith(INTERNAL_PREFIXES):
        return f"SKIP (local/internal): {action}@{ref}"
    if ref.startswith("sha256:"):
        return f"SKIP (already digest-pinned): {action}@{ref}"
    if SHA40_RE.match(ref):
        return f"SKIP (already SHA-pinned): {action}@{ref}"
    if "/" in ref or "\\" in ref:
        return f"SKIP (branch/composite ref, resolve manually): {action}@{ref}"

    sha = resolve_action_ref(action, ref)
    if sha is None:
        return f"ERROR: tag '{ref}' not found or unresolvable for {action}"
    return f"{action}@{sha} # {ref}"


# ---------------------------------------------------------------------------
# dependabot tag -> SHA auto-remediation (fix)
# ---------------------------------------------------------------------------

TAG_USES_RE = re.compile(
    r"^(\s*(?:-\s*)?uses:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)@([^\s#]+)(\s*#.*)?$"
)


def should_skip_action(action: str, ref: str) -> str | None:
    """Return a skip reason string if the action ref should not be remediated, else None."""
    if action.startswith(LOCAL_PREFIXES) or action.startswith(INTERNAL_PREFIXES):
        return f"SKIP (local/internal): {action}@{ref}"
    if ref.startswith("sha256:"):
        return f"SKIP (already digest-pinned): {action}@{ref}"
    if SHA40_RE.match(ref):
        return f"SKIP (already SHA-pinned): {action}@{ref}"
    if "/" in ref or "\\" in ref:
        return f"SKIP (branch/composite ref): {action}@{ref}"
    return None


def fix_uses_line(line: str) -> str | None:
    """Convert one tag-based ``uses:`` line to a SHA pin.

    Returns the new line text, or ``None`` if the line should be left unchanged.
    """
    m = TAG_USES_RE.match(line)
    if not m:
        return None
    prefix, action, ref, trailing = m.groups()
    ref = ref.split("#")[0].strip()
    skip = should_skip_action(action, ref)
    if skip is not None:
        return None
    sha = resolve_action_ref(action, ref)
    if sha is None:
        return None
    tag = ref
    return f"{prefix}{action}@{sha} # {tag}{trailing or ''}"


def fix_file(path: Path) -> list[tuple[str, str]]:
    """Fix every tag-based ``uses:`` line in ``path`` in place.

    Returns a list of ``(old_line, new_line)`` pairs that were changed.
    """
    text = path.read_text()
    lines = text.split("\n")
    changes: list[tuple[str, str]] = []
    for i, line in enumerate(lines):
        new_line = fix_uses_line(line)
        if new_line is not None and new_line != line:
            changes.append((line, new_line))
            lines[i] = new_line
    if changes:
        path.write_text("\n".join(lines))
    return changes


def detect_tag_uses(path: Path) -> list[tuple[int, str]]:
    """Return [(line_no, line)] for every tag-based ``uses:`` in ``path``.

    Skips already-SHA-pinned, local (./...), internal (Fadil369/B.I.Lab/...),
    digest-pinned, and branch/composite refs -- exactly what ``fix`` remediates.
    Used by ``fix --check`` as the CI-side Dependabot regression detector.
    """
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(path.read_text().split("\n"), start=1):
        m = TAG_USES_RE.match(line)
        if not m:
            continue
        prefix, action, ref, trailing = m.groups()
        ref = ref.split("#")[0].strip()
        if should_skip_action(action, ref) is not None:
            continue
        hits.append((i, line.rstrip()))
    return hits


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="BrainSAIT workflow guardrail: enforce CLAUDE.md conventions + resolve dependabot tag->SHA."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="validate workflow convention compliance")
    p_check.add_argument(
        "--include-examples",
        action="store_true",
        help="also lint examples/ caller workflows",
    )
    p_check.add_argument("paths", nargs="*", help="workflow files to inspect")

    p_resolve = sub.add_parser("resolve", help="resolve tag-based uses to SHA pins")
    p_resolve.add_argument("uses_lines", nargs="+", help="uses: lines to resolve")

    p_fix = sub.add_parser(
        "fix",
        help="auto-remediate: convert tag-based uses to SHA pins in place",
    )
    p_fix.add_argument(
        "--include-examples",
        action="store_true",
        help="also remediate examples/ caller workflows",
    )
    p_fix.add_argument(
        "--check",
        action="store_true",
        help="CI-side Dependabot regression detector: detect tag-based uses without modifying files; exit 1 if found",
    )
    p_fix.add_argument(
        "--commit",
        action="store_true",
        help="git commit the remediated files after fixing",
    )
    p_fix.add_argument("paths", nargs="*", help="workflow files to remediate")

    args = parser.parse_args(argv)

    if args.command == "resolve":
        for line in args.uses_lines:
            print(resolve_tag_to_sha(line))
        return 0

    if args.command == "fix":
        # --check: CI-side Dependabot regression detector. Detect tag-based uses
        # without modifying files; exit 1 so CI fails the PR before a tag bump lands.
        if args.check:
            if args.paths:
                files = [Path(p) for p in args.paths]
            else:
                files = sorted(Path(".github/workflows").glob("*.yml"))
                if args.include_examples:
                    files += sorted(Path("examples").glob("*.yml"))

            if not files:
                sys.stderr.write("guard_workflows: no workflow files found\n")
                return 2

            total_hits = 0
            for f in files:
                hits = detect_tag_uses(f)
                for line_no, line in hits:
                    sys.stdout.write(f"DEPENDABOT-TAG: {f}:{line_no}: {line}\n")
                    total_hits += 1

            if total_hits:
                sys.stdout.write(
                    f"\nguard_workflows fix --check: {total_hits} tag-based use(s) across "
                    f"{len(files)} file(s) -- run 'fix --commit' to remediate.\n"
                )
                return 1
            sys.stdout.write(
                f"guard_workflows fix --check: no tag-based uses across {len(files)} file(s) (clean).\n"
            )
            return 0

        if args.paths:
            files = [Path(p) for p in args.paths]
        else:
            files = sorted(Path(".github/workflows").glob("*.yml"))
            if args.include_examples:
                files += sorted(Path("examples").glob("*.yml"))

        if not files:
            sys.stderr.write("guard_workflows: no workflow files found\n")
            return 2

        total_changed = 0
        for f in files:
            changes = fix_file(f)
            for old, new in changes:
                sys.stdout.write(f"FIXED: {f}\n  from: {old}\n  to:   {new}\n")
            total_changed += len(changes)

        if total_changed:
            sys.stdout.write(
                f"\nguard_workflows: remediated {total_changed} use(s) across {len(files)} file(s).\n"
            )
        else:
            sys.stdout.write(
                f"guard_workflows: no tag-based uses found across {len(files)} file(s) (already clean).\n"
            )

        if args.commit and total_changed:
            commit_msg = (
                "chore(guardrail): auto-remediate dependabot tag bumps to SHA pins\n\n"
                "Close the detect -> resolve -> remediate loop: every tag-based\n"
                "uses: is pinned to its commit SHA with a trailing version comment,\n"
                "per CLAUDE.md workflow conventions."
            )
            try:
                subprocess.check_call(["git", "add"] + [str(f) for f in files])
                subprocess.check_call(["git", "commit", "-m", commit_msg])
                sys.stdout.write("guard_workflows: committed remediated files.\n")
            except subprocess.CalledProcessError as exc:
                sys.stderr.write(f"guard_workflows: git commit failed: {exc}\n")
                return 1
        return 0

    if args.paths:
        files = [Path(p) for p in args.paths]
    else:
        files = sorted(Path(".github/workflows").glob("*.yml"))
        if args.include_examples:
            files += sorted(Path("examples").glob("*.yml"))

    if not files:
        sys.stderr.write("guard_workflows: no workflow files found\n")
        return 2

    all_errors: list[str] = []
    for f in files:
        all_errors += check_file(f)

    if all_errors:
        for err in all_errors:
            sys.stderr.write(f"FAIL: {err}\n")
        sys.stderr.write(
            f"\nguard_workflows: {len(all_errors)} violation(s) across {len(files)} file(s).\n"
        )
        return 1

    scope = "workflows" + (" + examples" if args.include_examples else "")
    sys.stdout.write(f"guard_workflows: {len(files)} {scope} file(s) passed all CLAUDE.md conventions.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
