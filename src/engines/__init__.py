"""
SOC Command Center: 5 Advanced Cyber Engines.
All engines are live-only; no mock data. Empty results = verified 0 findings.
"""
from src.engines.supply_chain_engine import run_supply_chain_audit
from src.engines.ollama_fuzz_engine import run_ollama_fuzz
from src.engines.bola_idor_engine import run_bola_idor
from src.engines.osint_engine import run_osint_crawl
from src.engines.asm_engine import run_attack_surface_scan
from src.engines import remediation_engine

__all__ = [
    "run_supply_chain_audit",
    "run_ollama_fuzz",
    "run_bola_idor",
    "run_osint_crawl",
    "run_attack_surface_scan",
    "remediation_engine",
]

ENGINE_IDS = ["supply_chain", "ollama_fuzz", "bola_idor", "osint", "asm"]
