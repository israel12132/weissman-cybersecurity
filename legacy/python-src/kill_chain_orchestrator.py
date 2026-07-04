"""
Weissman-cybersecurity: Kill Chain Orchestrator.
Full MITRE ATT&CK kill chain orchestration across 7 phases.
Maps engine IDs to kill chain phases, auto-chains findings, computes risk scores.
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase → Engine mapping
# ---------------------------------------------------------------------------

PHASE_ENGINE_MAP: dict[str, list[str]] = {
    "reconnaissance": [
        "osint",
        "asm",
        "recon",
        "leak_hunter",
        "discovery_engine",
        "subdomain_takeover",
        "cve_scanner",
        "supply_chain_scanner",
        "phishing_kit_scanner",
        "github_monitor",
    ],
    "weaponization": [
        "payload_generator",
        "exploit_db_lookup",
        "zero_day_finder",
        "malware_generator",
        "ransomware_simulation",
        "cve_scanner",
        "supply_chain_scanner",
        "phishing_kit_scanner",
        "keylogger_engine",
    ],
    "delivery": [
        "phishing_kit_scanner",
        "payload_generator",
        "xss_engine",
        "open_redirect",
        "ssrf_engine",
        "oauth2_scanner",
        "sqli_engine",
        "xxe_engine",
        "supply_chain_scanner",
        "exploit_db_lookup",
    ],
    "exploitation": [
        "sqli_engine",
        "xss_engine",
        "ssrf_engine",
        "xxe_engine",
        "rce_engine",
        "lfi_rfi_engine",
        "bola_idor",
        "open_redirect",
        "zero_day_finder",
        "exploit_db_lookup",
        "oauth2_scanner",
    ],
    "installation": [
        "malware_generator",
        "rootkit_scanner",
        "keylogger_engine",
        "ransomware_simulation",
        "supply_chain_scanner",
        "privilege_escalation",
        "pass_the_hash",
        "mimikatz_sim",
        "memory_dumper",
    ],
    "command_and_control": [
        "c2_beacon_simulator",
        "dns_c2_tunnel",
        "https_c2_beacon",
        "covert_channel_engine",
        "lateral_movement_sim",
        "privilege_escalation",
        "pass_the_hash",
        "mimikatz_sim",
        "memory_dumper",
    ],
    "exfiltration": [
        "data_exfil_engine",
        "covert_channel_engine",
        "cloud_exfil",
        "dns_c2_tunnel",
        "https_c2_beacon",
        "memory_dumper",
        "lateral_movement_sim",
        "c2_beacon_simulator",
    ],
}

# ---------------------------------------------------------------------------
# MITRE tactic mapping
# ---------------------------------------------------------------------------

MITRE_TACTIC_MAP: dict[str, list[dict[str, str]]] = {
    "reconnaissance": [
        {"id": "TA0043", "name": "Reconnaissance"},
    ],
    "weaponization": [
        {"id": "TA0001", "name": "Initial Access"},
        {"id": "TA0002", "name": "Execution"},
    ],
    "delivery": [
        {"id": "TA0001", "name": "Initial Access"},
        {"id": "TA0042", "name": "Resource Development"},
    ],
    "exploitation": [
        {"id": "TA0002", "name": "Execution"},
        {"id": "TA0004", "name": "Privilege Escalation"},
        {"id": "TA0006", "name": "Credential Access"},
    ],
    "installation": [
        {"id": "TA0003", "name": "Persistence"},
        {"id": "TA0005", "name": "Defense Evasion"},
    ],
    "command_and_control": [
        {"id": "TA0011", "name": "Command and Control"},
        {"id": "TA0008", "name": "Lateral Movement"},
    ],
    "exfiltration": [
        {"id": "TA0010", "name": "Exfiltration"},
        {"id": "TA0040", "name": "Impact"},
    ],
}

# Ordered phase sequence for chaining
_PHASE_SEQUENCE: list[str] = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "exfiltration",
]

# Mapping of broad vuln_type keywords → phases where they are most relevant
_VULN_TYPE_PHASE_AFFINITY: dict[str, str] = {
    "sqli": "exploitation",
    "xss": "delivery",
    "ssrf": "exploitation",
    "xxe": "exploitation",
    "rce": "exploitation",
    "lfi": "exploitation",
    "rfi": "exploitation",
    "idor": "exploitation",
    "bola": "exploitation",
    "open_redirect": "delivery",
    "phishing": "delivery",
    "subdomain": "reconnaissance",
    "osint": "reconnaissance",
    "c2": "command_and_control",
    "exfil": "exfiltration",
    "malware": "installation",
    "rootkit": "installation",
    "privesc": "installation",
    "credential": "installation",
    "lateral": "command_and_control",
    "ransomware": "exfiltration",
    "keylogger": "installation",
}

# Representative MITRE technique IDs per phase
_PHASE_TECHNIQUES: dict[str, list[str]] = {
    "reconnaissance": ["T1595", "T1592", "T1589", "T1591", "T1598"],
    "weaponization": ["T1587", "T1588", "T1583", "T1584"],
    "delivery": ["T1566", "T1189", "T1190", "T1195", "T1199"],
    "exploitation": ["T1190", "T1059", "T1203", "T1068", "T1210"],
    "installation": ["T1543", "T1053", "T1055", "T1547", "T1574"],
    "command_and_control": ["T1071", "T1095", "T1090", "T1132", "T1572"],
    "exfiltration": ["T1041", "T1048", "T1567", "T1020", "T1030"],
}

# All MITRE tactics used in this module
_ALL_TACTICS: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class KillChainOrchestrator:
    """
    Orchestrates a full 7-phase MITRE ATT&CK kill chain.

    Provides phase-to-engine mapping, finding-driven phase chaining,
    composite risk scoring, attack-path simulation, and MITRE coverage
    reporting.
    """

    phase_engine_map: dict[str, list[str]] = field(
        default_factory=lambda: dict(PHASE_ENGINE_MAP)
    )
    mitre_tactic_map: dict[str, list[dict[str, str]]] = field(
        default_factory=lambda: dict(MITRE_TACTIC_MAP)
    )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def get_phase_engines(self, phase: str) -> list[str]:
        """Return the list of engine IDs assigned to *phase*."""
        return self.phase_engine_map.get(phase.lower(), [])

    def auto_chain(
        self, findings: list[dict[str, Any]], current_phase: str
    ) -> list[str]:
        """
        Given scan findings and the current kill-chain phase, return the
        recommended engine IDs for the **next** phase.

        Chaining logic:
        - Any critical/high finding triggers progression to the next phase.
        - The vuln_type of each finding biases which phase engines are
          preferred (e.g. web findings emphasise delivery/exploitation).
        - Returns an empty list if already at exfiltration.
        """
        phase = current_phase.lower()
        if phase not in _PHASE_SEQUENCE:
            logger.warning("Unknown phase %r – returning empty chain.", phase)
            return []

        idx = _PHASE_SEQUENCE.index(phase)
        if idx >= len(_PHASE_SEQUENCE) - 1:
            return []  # already at last phase

        # Check whether any finding warrants progression
        has_critical_or_high = any(
            f.get("severity", "").lower() in ("critical", "high") for f in findings
        )
        if not has_critical_or_high:
            return []

        next_phase = _PHASE_SEQUENCE[idx + 1]
        next_engines: list[str] = list(self.phase_engine_map.get(next_phase, []))

        # Collect vuln-type affinities from findings
        relevant_phases: set[str] = set()
        for f in findings:
            vtype = f.get("vuln_type", "").lower()
            for keyword, affinity_phase in _VULN_TYPE_PHASE_AFFINITY.items():
                if keyword in vtype:
                    relevant_phases.add(affinity_phase)

        # If any affinity phase is beyond next_phase, also include those engines
        enriched: list[str] = list(next_engines)
        for aff_phase in relevant_phases:
            if aff_phase in _PHASE_SEQUENCE and aff_phase != next_phase:
                for eng in self.phase_engine_map.get(aff_phase, []):
                    if eng not in enriched:
                        enriched.append(eng)

        return enriched

    def compute_chain_risk_score(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Compute a composite kill-chain risk score from a list of findings.

        Returns
        -------
        dict with keys:
            overall_score, cvss_weighted_score, kill_chain_coverage,
            estimated_dwell_time_hours, risk_level, phase_scores,
            critical_count, high_count
        """
        if not findings:
            return self._empty_risk_score()

        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")

        # CVSS-weighted score
        cvss_scores = [float(f.get("cvss_score", 0.0)) for f in findings]
        if cvss_scores:
            max_cvss = max(cvss_scores)
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            cvss_weighted = (max_cvss * 0.6 + avg_cvss * 0.4) * 10  # scale to 100
        else:
            cvss_weighted = 0.0

        # Kill-chain phase coverage
        covered_phases: set[str] = set()
        for f in findings:
            vtype = f.get("vuln_type", "").lower()
            for keyword, phase in _VULN_TYPE_PHASE_AFFINITY.items():
                if keyword in vtype:
                    covered_phases.add(phase)
        # Also infer phase from severity: critical findings imply exploitation+
        if critical_count > 0:
            covered_phases.update({"exploitation", "installation"})
        kill_chain_coverage = len(covered_phases) / len(_PHASE_SEQUENCE)

        # Per-phase scores (0-100) based on relevant findings
        phase_scores: dict[str, float] = {}
        for phase in _PHASE_SEQUENCE:
            phase_findings = [
                f for f in findings
                if any(
                    kw in f.get("vuln_type", "").lower()
                    for kw, p in _VULN_TYPE_PHASE_AFFINITY.items()
                    if p == phase
                )
            ]
            if phase_findings:
                phase_cvss = [float(f.get("cvss_score", 5.0)) for f in phase_findings]
                phase_scores[phase] = min(100.0, sum(phase_cvss) / len(phase_cvss) * 10)
            else:
                phase_scores[phase] = 0.0

        # Overall score: blend severity counts, CVSS, and coverage
        severity_component = min(100.0, critical_count * 20 + high_count * 8 + medium_count * 3)
        coverage_component = kill_chain_coverage * 100
        overall_score = (
            severity_component * 0.45
            + cvss_weighted * 0.35
            + coverage_component * 0.20
        )
        overall_score = min(100.0, overall_score)

        # Estimated dwell time (hours): higher coverage → longer dwell
        base_dwell = 24.0
        dwell_multiplier = 1 + (kill_chain_coverage * 3) + (critical_count * 0.5)
        estimated_dwell_time_hours = base_dwell * dwell_multiplier

        risk_level = self._score_to_risk_level(overall_score)

        return {
            "overall_score": round(overall_score, 2),
            "cvss_weighted_score": round(cvss_weighted, 2),
            "kill_chain_coverage": round(kill_chain_coverage * 100, 1),
            "estimated_dwell_time_hours": round(estimated_dwell_time_hours, 1),
            "risk_level": risk_level,
            "phase_scores": {k: round(v, 2) for k, v in phase_scores.items()},
            "critical_count": critical_count,
            "high_count": high_count,
        }

    def simulate_attack_path(
        self, entry_point: str, target: str
    ) -> list[dict[str, Any]]:
        """
        Simulate a full 7-phase attack path from *entry_point* to *target*.

        Returns a list of phase dicts, each containing:
            phase, likelihood_score, estimated_duration_hours,
            engines_used, key_techniques, risk_contribution
        """
        path: list[dict[str, Any]] = []
        cumulative_likelihood = 1.0

        for i, phase in enumerate(_PHASE_SEQUENCE):
            # Likelihood degrades through the chain (harder to reach later phases)
            phase_likelihood = cumulative_likelihood * random.uniform(0.55, 0.90)
            cumulative_likelihood = phase_likelihood

            techniques = list(_PHASE_TECHNIQUES.get(phase, []))
            engines = list(self.phase_engine_map.get(phase, []))[:4]

            # Duration increases for later phases (deeper in the network)
            base_hours = [2, 4, 6, 12, 24, 48, 8]
            estimated_hours = base_hours[i] * random.uniform(0.8, 1.5)

            risk_contribution = round(phase_likelihood * (10 - i) * 5, 2)

            path.append(
                {
                    "phase": phase,
                    "likelihood_score": round(phase_likelihood, 4),
                    "estimated_duration_hours": round(estimated_hours, 1),
                    "engines_used": engines,
                    "key_techniques": techniques[:3],
                    "risk_contribution": min(100.0, risk_contribution),
                    "entry_point": entry_point if i == 0 else None,
                    "target": target if i == len(_PHASE_SEQUENCE) - 1 else None,
                }
            )

        logger.info(
            "Simulated attack path from %r to %r across %d phases.",
            entry_point,
            target,
            len(path),
        )
        return path

    def get_mitre_coverage(self, engine_ids: list[str]) -> dict[str, Any]:
        """
        Compute MITRE ATT&CK coverage for the given *engine_ids*.

        Returns
        -------
        dict with: tactics_covered, techniques, coverage_percentage, uncovered_tactics
        """
        engine_set = set(engine_ids)
        covered_tactics: set[str] = set()
        covered_techniques: list[str] = []

        for phase, engines in self.phase_engine_map.items():
            if any(e in engine_set for e in engines):
                for tactic in self.mitre_tactic_map.get(phase, []):
                    covered_tactics.add(tactic["name"])
                for technique in _PHASE_TECHNIQUES.get(phase, []):
                    if technique not in covered_techniques:
                        covered_techniques.append(technique)

        uncovered = [t for t in _ALL_TACTICS if t not in covered_tactics]
        coverage_pct = len(covered_tactics) / len(_ALL_TACTICS) * 100

        return {
            "tactics_covered": sorted(covered_tactics),
            "techniques": covered_techniques,
            "coverage_percentage": round(coverage_pct, 1),
            "uncovered_tactics": uncovered,
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _score_to_risk_level(score: float) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    @staticmethod
    def _empty_risk_score() -> dict[str, Any]:
        return {
            "overall_score": 0.0,
            "cvss_weighted_score": 0.0,
            "kill_chain_coverage": 0.0,
            "estimated_dwell_time_hours": 0.0,
            "risk_level": "low",
            "phase_scores": {p: 0.0 for p in _PHASE_SEQUENCE},
            "critical_count": 0,
            "high_count": 0,
        }
