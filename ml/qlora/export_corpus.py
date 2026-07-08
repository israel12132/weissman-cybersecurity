#!/usr/bin/env python3
"""
Export a QLoRA instruction-tuning corpus from Weissman's institutional memory.

Turns the platform's *own* accumulated wins — Supreme-Council strategies, WAF-bypass
syntheses, confirmed pentest payloads, and validated Genesis vaccines — into JSONL
instruction/response pairs. Fine-tuning a small open-weight base on this corpus produces
a security-specialised local model: "the brain that is yours", trained on what worked
in your environment, running fully on-box (no external API, no data egress).

Usage:
    DATABASE_URL=postgres://weissman_app:...@host/weissman \\
        python export_corpus.py --out corpus.jsonl [--tenant 1] [--min-wins 1]

Each line is: {"instruction": "...", "input": "...", "output": "...", "source": "..."}
Only real, persisted rows are exported — never fabricated examples.
"""
import argparse
import json
import os
import sys

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    sys.exit("pip install psycopg2-binary  (see requirements.txt)")


def rows(cur, sql, params=()):
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception as e:  # table may not exist on older schemas — skip gracefully
        sys.stderr.write(f"[skip] {e}\n")
        return []


def export(conn, tenant, min_wins):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    tclause = "AND tenant_id = %s" if tenant is not None else ""
    tparam = (tenant,) if tenant is not None else ()
    out = []

    # 1) Supreme-Council winning strategies
    for r in rows(cur, f"""
        SELECT target_fingerprint, brief_excerpt, strategy_summary
        FROM supreme_council_memory
        WHERE COALESCE(strategy_summary,'') <> '' {tclause}
    """, tparam):
        out.append({
            "instruction": f"You are Weissman's Sovereign General. For a target with "
                           f"fingerprint '{r['target_fingerprint']}', propose the winning "
                           f"offensive strategy.",
            "input": r.get("brief_excerpt") or "",
            "output": r["strategy_summary"],
            "source": "supreme_council_memory",
        })

    # 2) WAF-bypass syntheses (Critic -> Hacker)
    for r in rows(cur, f"""
        SELECT failure_context, critic_waf_analysis, hacker_polymorphic_payload
        FROM sovereign_learning_buffer
        WHERE status = 'synthesized'
          AND COALESCE(hacker_polymorphic_payload,'') <> '' {tclause}
    """, tparam):
        out.append({
            "instruction": "A probe was blocked by a WAF. Given the failure context and the "
                           "critic's analysis, produce a refined polymorphic bypass.",
            "input": f"failure_context: {r.get('failure_context')}\n"
                     f"critic: {r.get('critic_waf_analysis')}",
            "output": r["hacker_polymorphic_payload"],
            "source": "sovereign_learning_buffer",
        })

    # 3) Confirmed pentest payloads (replay-proven wins)
    for r in rows(cur, f"""
        SELECT engine, cwe, vuln_signature, payload, evidence_summary,
               target_fingerprint, won_count
        FROM pentest_winning_paths
        WHERE COALESCE(payload,'') <> '' AND won_count >= %s {tclause}
    """, (min_wins, *tparam)):
        out.append({
            "instruction": f"For target '{r['target_fingerprint']}' using engine "
                           f"'{r['engine']}' (CWE {r['cwe'] or 'n/a'}, {r['vuln_signature']}), "
                           f"produce a payload that confirms the vulnerability.",
            "input": "",
            "output": f"{r['payload']}\n\nEvidence: {r.get('evidence_summary') or ''}".strip(),
            "source": "pentest_winning_paths",
        })

    # 4) Validated Genesis vaccines (attack chain + remediation)
    for r in rows(cur, f"""
        SELECT tech_fingerprint, component_ref, attack_chain_json, remediation_patch, severity
        FROM genesis_vaccine_vault
        WHERE preemptive_validated = TRUE
          AND COALESCE(attack_chain_json::text,'') <> '' {tclause}
    """, tparam):
        chain = r.get("attack_chain_json")
        out.append({
            "instruction": f"For component '{r.get('component_ref')}' on stack "
                           f"'{r.get('tech_fingerprint')}', describe the attack chain and the "
                           f"remediation patch.",
            "input": "",
            "output": f"Attack chain: {json.dumps(chain) if chain else ''}\n"
                      f"Remediation: {r.get('remediation_patch') or ''}\n"
                      f"Severity: {r.get('severity') or ''}".strip(),
            "source": "genesis_vaccine_vault",
        })

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="corpus.jsonl")
    ap.add_argument("--tenant", type=int, default=None, help="limit to one tenant id")
    ap.add_argument("--min-wins", type=int, default=1, help="min won_count for pentest paths")
    args = ap.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        sys.exit("set DATABASE_URL")

    conn = psycopg2.connect(dsn)
    examples = export(conn, args.tenant, args.min_wins)
    with open(args.out, "w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    by_source = {}
    for ex in examples:
        by_source[ex["source"]] = by_source.get(ex["source"], 0) + 1
    print(f"wrote {len(examples)} examples -> {args.out}")
    for s, n in sorted(by_source.items()):
        print(f"  {s}: {n}")
    if len(examples) < 200:
        print("\nNOTE: <200 examples. QLoRA works best with 1k+; keep running the platform "
              "so the memory tables grow, then re-export.")


if __name__ == "__main__":
    main()
