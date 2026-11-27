#!/usr/bin/env python3
"""Static security checks for GitHub Actions workflows in .github/workflows/.

Fails (exit code 1) if any workflow in .github/workflows/*.yml:
  1. Interpolates ``${{ ... }}`` directly inside a ``run:`` shell script block
     (or inside ``cloudflare/wrangler-action`` command inputs).
  2. References a third-party GitHub Action by mutable tag/branch instead of a
     full 40-character hexadecimal commit SHA (local ``./...`` and internal
     ``Fadil369/B.I.Lab/...`` workflow references are permitted).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable

PINNED_ACTION_RE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
PINNED_DOCKER_RE = re.compile(r"^docker://.+@sha256:[0-9a-f]{64}$")
WRANGLER_COMMAND_KEYS = {"command", "preCommands", "postCommands"}


def is_valid_uses(ref: str) -> bool:
    """Return True if ``uses:`` is local, internal B.I.Lab, or SHA-pinned."""
    value = ref.strip()
    if value.startswith("./") or value.startswith("Fadil369/B.I.Lab/"):
        return True
    if value.startswith("docker://"):
        return bool(PINNED_DOCKER_RE.match(value))
    return bool(PINNED_ACTION_RE.match(value))


def _check_with_pyyaml(path: Path, text: str) -> list[str]:
    import yaml  # type: ignore[import-untyped]
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode

    errors: list[str] = []
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as exc:
        return [f"{path}: invalid YAML: {exc}"]

    if not isinstance(root, MappingNode):
        return errors

    def get_map_entry(node: MappingNode, key: str):
        for k_node, v_node in node.value:
            if isinstance(k_node, ScalarNode) and k_node.value == key:
                return v_node
        return None

    jobs_node = get_map_entry(root, "jobs")
    if not isinstance(jobs_node, MappingNode):
        return errors

    for _job_name_node, job_node in jobs_node.value:
        if not isinstance(job_node, MappingNode):
            continue

        job_uses = get_map_entry(job_node, "uses")
        if isinstance(job_uses, ScalarNode):
            if not is_valid_uses(job_uses.value):
                line = job_uses.start_mark.line + 1
                errors.append(
                    f"{path}:{line}: unpinned job uses '{job_uses.value}' "
                    "(must be full 40-char commit SHA, './...', or 'Fadil369/B.I.Lab/...')"
                )

        steps_node = get_map_entry(job_node, "steps")
        if not isinstance(steps_node, SequenceNode):
            continue

        for step_node in steps_node.value:
            if not isinstance(step_node, MappingNode):
                continue

            run_node = get_map_entry(step_node, "run")
            if isinstance(run_node, ScalarNode) and "${{" in run_node.value:
                line = run_node.start_mark.line + 1
                errors.append(
                    f"{path}:{line}: expression interpolation '${{{{' inside 'run:' block "
                    "(pass untrusted or caller values via 'env:' instead)"
                )

            step_uses = get_map_entry(step_node, "uses")
            if isinstance(step_uses, ScalarNode):
                if not is_valid_uses(step_uses.value):
                    line = step_uses.start_mark.line + 1
                    errors.append(
                        f"{path}:{line}: unpinned action uses '{step_uses.value}' "
                        "(must be full 40-char commit SHA)"
                    )
                if step_uses.value.startswith("cloudflare/wrangler-action@"):
                    with_node = get_map_entry(step_node, "with")
                    if isinstance(with_node, MappingNode):
                        for cmd_key in WRANGLER_COMMAND_KEYS:
                            cmd_node = get_map_entry(with_node, cmd_key)
                            if isinstance(cmd_node, ScalarNode) and "${{" in cmd_node.value:
                                line = cmd_node.start_mark.line + 1
                                errors.append(
                                    f"{path}:{line}: expression interpolation '${{{{' inside "
                                    f"wrangler-action '{cmd_key}'"
                                )

    return errors


def _strip_comment(value: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(value):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or value[idx - 1].isspace():
                return value[:idx].strip()
    return value.strip()


def _check_fallback(path: Path, text: str) -> list[str]:
    """Pure-stdlib line parser fallback when PyYAML is not installed."""
    errors: list[str] = []
    lines = text.splitlines()
    uses_re = re.compile(r"^\s*(?:-\s*)?uses:\s*(.+)$")
    run_re = re.compile(r"^(\s*)(-\s*)?run:\s*(.*)$")

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            idx += 1
            continue

        m_uses = uses_re.match(line)
        if m_uses:
            raw_val = _strip_comment(m_uses.group(1)).strip("\"'")
            if not is_valid_uses(raw_val):
                errors.append(
                    f"{path}:{idx + 1}: unpinned action uses '{raw_val}' "
                    "(must be full 40-char commit SHA)"
                )
            idx += 1
            continue

        m_run = run_re.match(line)
        if m_run:
            key_indent = len(m_run.group(1)) + len(m_run.group(2) or "")
            rest = _strip_comment(m_run.group(3))
            if rest == "":
                # Could be `defaults:\n  run:\n    working-directory: ...` mapping
                idx += 1
                continue
            if rest[0] in ("|", ">"):
                idx += 1
                while idx < len(lines):
                    sub = lines[idx]
                    if not sub.strip():
                        idx += 1
                        continue
                    sub_indent = len(sub) - len(sub.lstrip(" "))
                    if sub_indent <= key_indent:
                        break
                    if "${{" in sub:
                        errors.append(
                            f"{path}:{idx + 1}: expression interpolation '${{{{' inside 'run:' block"
                        )
                    idx += 1
                continue
            if "${{" in rest:
                errors.append(
                    f"{path}:{idx + 1}: expression interpolation '${{{{' inside 'run:' block"
                )
        idx += 1

    return errors


def check_files(paths: Iterable[Path]) -> list[str]:
    try:
        import yaml as _yaml  # noqa: F401
        checker = _check_with_pyyaml
    except ImportError:
        checker = _check_fallback

    all_errors: list[str] = []
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        all_errors.extend(checker(path, text))
    return all_errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint GitHub Actions workflows for security rules.")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Workflow files to inspect (defaults to .github/workflows/*.yml)",
    )
    args = parser.parse_args(argv)
    if args.paths:
        files = [Path(p) for p in args.paths]
    else:
        files = sorted(Path(".github/workflows").glob("*.yml"))

    if not files:
        sys.stderr.write("error: no workflow files found\n")
        return 2

    errors = check_files(files)
    if errors:
        for err in errors:
            sys.stderr.write(f"FAIL: {err}\n")
        sys.stderr.write(f"\nlint_workflows: {len(errors)} violation(s) across {len(files)} file(s).\n")
        return 1

    sys.stdout.write(f"lint_workflows: {len(files)} workflow file(s) passed security checks.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
