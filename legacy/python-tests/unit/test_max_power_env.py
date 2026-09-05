"""Max-power env fragment: no secrets, live-only, apply/verify roundtrip."""

from __future__ import annotations

import subprocess
from pathlib import Path

def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for p in [here.parent, *here.parents]:
        if (p / "deploy" / "env.max-power.env").is_file():
            return p
    raise RuntimeError("could not find repo root from test path")


REPO = _repo_root()
FRAG = REPO / "deploy" / "env.max-power.env"
APPLY = REPO / "scripts" / "apply_max_power_env.sh"
VERIFY = REPO / "scripts" / "verify_max_power_env.sh"


def _parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def test_fragment_exists_and_has_core_capability_flags():
    assert FRAG.is_file()
    vals = _parse_kv(FRAG.read_text())
    assert vals["WEISSMAN_GENESIS_PROTOCOL"] == "1"
    assert vals["WEISSMAN_SOVEREIGN_EVOLUTION"] == "1"
    assert vals["WEISSMAN_SUPREME_COUNCIL"] == "1"
    assert vals["WEISSMAN_GENERATIVE_FUZZ"] == "1"
    assert vals["WEISSMAN_SELF_IMPROVE"] == "1"
    assert vals["WEISSMAN_SCANNING_ENABLED"] == "1"
    assert vals["WEISSMAN_LLM_MODEL"] == "gpt-4o"
    assert vals["WEISSMAN_WORKER_HEAVY_CONCURRENCY"] == "6"
    assert vals["WEISSMAN_WORKER_LIGHT_CONCURRENCY"] == "16"


def test_fragment_forces_off_fake_and_insecure_flags():
    vals = _parse_kv(FRAG.read_text())
    assert vals["WEISSMAN_ADVISORY_FINDINGS"] == "0"
    assert vals["WEISSMAN_STEALTH_DISABLED"] == "0"
    assert vals["WEISSMAN_ALLOW_INSECURE_TLS"] == "0"
    assert vals["WEISSMAN_HEAL_AUTO_MERGE"] == "0"
    assert vals["WEISSMAN_AUTOHEAL_SKIP_SANDBOX"] == "0"
    assert vals["WEISSMAN_SAML_INSECURE_SKIP_VERIFY"] == "0"
    assert vals["WEISSMAN_LIQUID_MATRIX_SDN_ENFORCED"] == "0"


def test_fragment_contains_no_secrets():
    text = FRAG.read_text()
    lowered = text.lower()
    assert "sk-proj-" not in lowered
    assert "sk_live" not in lowered
    for _k, v in _parse_kv(text).items():
        assert not v.startswith("sk-")
        assert "BEGIN " not in v


def test_apply_and_verify_roundtrip(tmp_path):
    dest = tmp_path / ".env"
    dest.write_text(
        "WEISSMAN_LLM_MODEL=gpt-4o-mini\nWEISSMAN_ADVISORY_FINDINGS=1\nKEEP_ME=yes\n"
    )
    applied = subprocess.run(
        ["bash", str(APPLY), str(dest)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert applied.returncode == 0, applied.stdout + applied.stderr
    verified = subprocess.run(
        ["bash", str(VERIFY), str(dest)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "ALL_MAX_POWER_KEYS_APPLIED" in verified.stdout
    have = _parse_kv(dest.read_text())
    assert have["KEEP_ME"] == "yes"
    assert have["WEISSMAN_ADVISORY_FINDINGS"] == "0"
    assert have["WEISSMAN_LLM_MODEL"] == "gpt-4o"
