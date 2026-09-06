#!/usr/bin/env python3
"""Contract test: the Mergify merge queue must require every blocking CI job.

WHY THIS EXISTS
.mergify.yml carries the comment "The check-success names below must match the
ci.yml job `name:` values exactly", and nothing checked it. Three blocking jobs —
Prometheus alert rules, Gateway security contract, Production launcher contract —
ran on every PR but were absent from the queue, so the queue could merge a PR
while they were red. A typo in a check name is worse: Mergify waits forever on a
check that will never report, or the condition is simply never satisfied.

Static check over the workflow YAML. No network.

    python3 scripts/verify_merge_queue_contract.py
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment guard
    print("error: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
MERGIFY = ROOT / ".mergify.yml"
WORKFLOWS = ROOT / ".github" / "workflows"

# Jobs that legitimately never gate a PR merge.
#   - Publish signed image: tags only, runs after merge.
#   - CodeQL "Analyze (...)" checks are matrix-generated, so they carry no
#     literal job `name:`; they are listed explicitly instead.
EXEMPT_JOB_NAMES = {"Publish signed image (tags only)"}
MATRIX_CHECKS = {"Analyze (javascript-typescript)", "Analyze (python)"}


def job_names(workflow: Path) -> set[str]:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
    names = set()
    for job_id, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict):
            names.add(str(job.get("name") or job_id))
    return names


def required_checks() -> dict[str, set[str]]:
    """check-success names per condition block in .mergify.yml."""
    doc = yaml.safe_load(MERGIFY.read_text(encoding="utf-8")) or {}
    blocks: dict[str, set[str]] = {}
    for rule in doc.get("queue_rules") or []:
        for key in ("queue_conditions", "merge_conditions"):
            found = {
                c.split("=", 1)[1]
                for c in (rule.get(key) or [])
                if isinstance(c, str) and c.startswith("check-success=")
            }
            blocks[f"{rule.get('name', '?')}.{key}"] = found
    return blocks


def main() -> int:
    errors: list[str] = []

    ci_jobs = job_names(WORKFLOWS / "ci.yml")
    gating_jobs = ci_jobs - EXEMPT_JOB_NAMES
    known_checks = ci_jobs | MATRIX_CHECKS

    blocks = required_checks()
    if not blocks:
        print("error: no queue_rules conditions found in .mergify.yml", file=sys.stderr)
        return 1

    for block, checks in sorted(blocks.items()):
        for unknown in sorted(checks - known_checks):
            errors.append(
                f"{block}: requires check {unknown!r}, which no ci.yml job produces "
                "(the queue would wait on it forever)"
            )
        for missing in sorted(gating_jobs - checks):
            errors.append(
                f"{block}: blocking CI job {missing!r} is not required; "
                "the queue could merge a PR while it is red"
            )

    # queue_conditions and merge_conditions must stay identical: the second is the
    # last gate before landing, and a subset there re-opens the same hole.
    per_rule: dict[str, list[tuple[str, set[str]]]] = {}
    for block, checks in blocks.items():
        rule, kind = block.rsplit(".", 1)
        per_rule.setdefault(rule, []).append((kind, checks))
    for rule, kinds in per_rule.items():
        if len(kinds) == 2 and kinds[0][1] != kinds[1][1]:
            diff = kinds[0][1].symmetric_difference(kinds[1][1])
            errors.append(
                f"{rule}: queue_conditions and merge_conditions differ on {sorted(diff)}"
            )

    if errors:
        print("Merge queue contract FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    total = len(next(iter(blocks.values())))
    print(f"Merge queue contract OK: {total} required checks cover every blocking ci.yml job")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
