"""
Unified Rust engine dispatch for the legacy Python layer.

All scan logic lives in the `fingerprint_engine` Rust binary. Python callers should
prefer `run_engine(engine_id, target)` over per-engine wrapper modules — the wrappers
remain for backward compatibility but emit DeprecationWarning on import.
"""
from __future__ import annotations

import warnings
from typing import Any

from src.engines._rust_runner import run_rust_engine

# Subset of production engine IDs exposed through the Python CLI layer.
# Full catalog (562+) is authoritative in backend/weissman-core/src/models/engine.rs.
_ENGINE_IDS_LEGACY = (
    "supply_chain",
    "ollama_fuzz",
    "bola_idor",
    "osint",
    "asm",
    "graphql_attack",
    "jwt_attack",
    "oauth_oidc",
    "http_smuggling",
    "prototype_pollution",
    "ssrf_advanced",
    "xxe",
    "ssti",
    "file_upload",
    "websocket_attack",
    "cache_poisoning",
    "llm_redteam",
    "adversarial_ml",
    "autonomous_pentest",
    "aws_attack",
    "azure_attack",
    "gcp_attack",
    "k8s_container",
    "iac_misconfig",
    "serverless_attack",
    "scada_ics",
    "iot_firmware",
    "ble_rf",
    "edr_evasion",
    "waf_bypass",
    "timing_sidechannel",
    "antiforensics",
    "pki_tls",
    "pqc_scanner",
    "password_spray",
    "kerberoasting",
    "saml_attack",
    "bgp_dns_hijacking",
    "ipv6_attack",
    "mtls_grpc",
    "smb_netbios",
    "cicd_pipeline",
    "container_registry",
    "sbom_analyzer",
    "typosquatting_monitor",
    "kill_chain",
    "oast_oob",
    "deception_honeypot",
    "digital_twin",
    "zero_day_prediction",
    "threat_emulation",
    "process_inventory",
    "usb_enumeration",
    "liquid_matrix",
    "sovereign_active_defense_fusion",
)
ENGINE_IDS: frozenset[str] = frozenset(_ENGINE_IDS_LEGACY)


def run_engine(engine_id: str, target: str, **kwargs: Any) -> dict:
    """
    Invoke any registered engine via the Rust fingerprint_engine binary.

    Returns ``{"status": "ok"|"error", "findings": [...], "message": "..."}``.
    """
    eid = (engine_id or "").strip()
    if not eid:
        return {"status": "error", "findings": [], "message": "engine_id required"}
    if eid not in ENGINE_IDS:
        return {
            "status": "error",
            "findings": [],
            "message": f"engine '{eid}' is not registered in the Python bridge — use the Command Center API or extend ENGINE_IDS in registry.py",
        }
    return run_rust_engine(eid, target, **kwargs)


def warn_legacy_wrapper(engine_id: str, module: str) -> None:
    warnings.warn(
        f"{module} is deprecated — call src.engines.registry.run_engine({engine_id!r}, target) instead",
        DeprecationWarning,
        stacklevel=3,
    )
