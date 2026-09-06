#!/usr/bin/env python3
"""Contract test: every CI step that boots weissman-server / weissman-worker in
production mode must supply the secrets `security_startup.rs` demands.

WHY THIS EXISTS
The nightly E2E set WEISSMAN_ADMIN_PASSWORD only on the steps that log IN to the
API, not on the steps that START the server and worker. Both processes therefore
hit `security policy refusal: WEISSMAN_ADMIN_PASSWORD must be set in production`
and exited instantly, and the job spent 180s in "Wait for API health" before
failing with no reason attached. That went unnoticed for seven consecutive
nights, because nothing compared the workflows against the boot contract.

This is a static check: it parses the workflow YAML, resolves the effective env
for each launching step (workflow env < job env < step env, exactly how GitHub
Actions layers them), and asserts the boot guards would pass. No network, no
Docker, no cargo — safe to run anywhere.

    python3 scripts/verify_ci_production_boot_env.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment guard
    print("error: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Mirrors WEAK_JWT_SECRETS in fingerprint_engine/src/security_startup.rs.
WEAK_JWT_SECRETS = {
    "change-me-in-production-docker",
    "changeme",
    "ci-engine-smoke-secret",
    "change_me_min_32_bytes_random_hex_or_base64",
}

# Mirrors WEAK_DB_PASSWORD_FRAGMENTS in the same module.
WEAK_DB_FRAGMENTS = ("weissman_dev_secret", "weissman_auth_dev", "weissman_ro_dev")
DB_URL_VARS = ("DATABASE_URL", "WEISSMAN_AUTH_DATABASE_URL", "WEISSMAN_READ_ONLY_DATABASE_URL")

TRUTHY = {"1", "true", "yes", "on"}

LAUNCH_PATTERNS = {
    "server": re.compile(r"target/(?:debug|release)/weissman-server|cargo run\b[^\n]*-p\s+weissman-server"),
    "worker": re.compile(r"target/(?:debug|release)/weissman-worker|cargo run\b[^\n]*-p\s+weissman-worker"),
}

# Jobs that must keep booting a production-mode stack. Deleting the launch step
# would otherwise make this gate vacuously green.
REQUIRED_LAUNCHES = {
    ("nightly-e2e.yml", "server"),
    ("nightly-e2e.yml", "worker"),
    ("ci.yml", "server"),
    ("ci.yml", "worker"),
}


def truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in TRUTHY


def as_env(raw) -> dict[str, str]:
    """Coerce a workflow `env:` mapping to str->str, dropping expressions."""
    if not isinstance(raw, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in raw.items()}


def check_min_len(env, var, minimum, errors, where):
    value = env.get(var)
    if value is None:
        errors.append(f"{where}: {var} is not set (production boot requires >= {minimum} chars)")
    elif len(value.strip()) < minimum:
        errors.append(
            f"{where}: {var} is {len(value.strip())} chars; production boot requires >= {minimum}"
        )


def check_non_empty(env, var, errors, where):
    if not env.get(var, "").strip():
        errors.append(f"{where}: {var} must be set and non-empty in production")


def check_step(workflow_name, job_name, step_name, role, env, errors):
    where = f"{workflow_name} :: {job_name} :: {step_name!r}"

    # Shared server+worker guards.
    check_min_len(env, "WEISSMAN_JWT_SECRET", 48, errors, where)
    jwt = env.get("WEISSMAN_JWT_SECRET", "").strip().lower()
    if jwt in WEAK_JWT_SECRETS:
        errors.append(f"{where}: WEISSMAN_JWT_SECRET matches a known weak value")
    check_min_len(env, "WEISSMAN_ADMIN_PASSWORD", 12, errors, where)
    check_min_len(env, "WEISSMAN_JOB_ORCHESTRATOR_SECRET", 32, errors, where)

    # Secrets-at-rest: the CEO vault specifically requires a 64-hex WEISSMAN_VAULT_KEY.
    vault = env.get("WEISSMAN_VAULT_KEY", "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", vault):
        errors.append(
            f"{where}: WEISSMAN_VAULT_KEY must be 64 hex chars "
            "(dedicated secrets-at-rest key; deriving from the JWT secret is refused)"
        )

    for var in DB_URL_VARS:
        url = env.get(var, "").lower()
        hit = next((frag for frag in WEAK_DB_FRAGMENTS if frag in url), None)
        if hit:
            errors.append(f"{where}: {var} contains the dev database password {hit!r}")

    if role != "server":
        return

    # Server-only guards.
    check_non_empty(env, "WEISSMAN_MIGRATE_URL", errors, where)
    check_min_len(env, "WEISSMAN_METRICS_TOKEN", 32, errors, where)
    check_min_len(env, "WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET", 32, errors, where)
    if not truthy(env.get("WEISSMAN_COOKIE_SECURE")):
        errors.append(f"{where}: WEISSMAN_COOKIE_SECURE must be 1 in production")
    if not env.get("REDIS_URL", "").strip() and not truthy(env.get("WEISSMAN_ALLOW_SINGLE_NODE")):
        errors.append(
            f"{where}: REDIS_URL must be set in production "
            "(or WEISSMAN_ALLOW_SINGLE_NODE=1 to acknowledge single-replica)"
        )


def main() -> int:
    errors: list[str] = []
    seen_launches: set[tuple[str, str]] = set()
    checked = 0

    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        workflow_env = as_env(doc.get("env"))

        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            job_env = {**workflow_env, **as_env(job.get("env"))}

            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                step_env = {**job_env, **as_env(step.get("env"))}
                step_name = step.get("name", run.strip().splitlines()[0][:60])

                for role, pattern in LAUNCH_PATTERNS.items():
                    if not pattern.search(run):
                        continue
                    seen_launches.add((path.name, role))
                    # Dev-mode launches are out of scope: the boot guards no-op.
                    if step_env.get("WEISSMAN_ENV", "").strip().lower() != "production":
                        continue
                    checked += 1
                    check_step(path.name, job_name, step_name, role, step_env, errors)

    for workflow, role in sorted(REQUIRED_LAUNCHES - seen_launches):
        errors.append(
            f"{workflow}: no step launches weissman-{role}; "
            "this gate would pass vacuously. Restore the launch or update REQUIRED_LAUNCHES."
        )

    if errors:
        print("CI production boot contract FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "\nThese are the guards in fingerprint_engine/src/security_startup.rs. "
            "A step missing any of them exits at boot, and the job then fails in a "
            "later health check with no cause attached.",
            file=sys.stderr,
        )
        return 1

    print(f"CI production boot contract OK: {checked} production launch step(s) satisfy security_startup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
