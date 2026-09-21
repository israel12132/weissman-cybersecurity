#!/usr/bin/env node
// Positive-control lock for the platform's headline integrity claim:
// "no fabricated or randomised findings — every persisted finding derives from a
// live probe." The finding-persistence, evidence-gate and threat-intel-enrichment
// modules compute the severity / risk_score / EPSS / KEV / proof that reach the
// `vulnerabilities` table. If ANY randomness entered those modules, a persisted
// finding's score or ordering could be fabricated. This gate fails the build if a
// randomness source is ever imported or used there, so the "deterministic, live-only"
// property cannot silently regress.
//
// Scope: exactly the modules on the persist/score/enrich path. Extend FILES (with a
// one-line justification) if a new module joins that path. A legitimate, non-scoring
// use of randomness elsewhere in the engine is unaffected — this gate is deliberately
// narrow.
//
// Usage: node scripts/verify_no_rand_in_scoring.mjs   (exit 1 on any hit)

import { readFileSync } from 'node:fs';

const FILES = [
  'fingerprint_engine/src/findings_persist.rs', // builds + writes every vulnerabilities row
  'fingerprint_engine/src/findings_gate.rs', // the evidence gate every write passes through
  'fingerprint_engine/src/intel_epss.rs', // EPSS/KEV enrichment folded into effective_risk
  'fingerprint_engine/src/intel_findings_backfill.rs', // live worker: UPDATEs vulnerabilities epss_score/kev_listed and re-ranks effective_risk
  'fingerprint_engine/src/intel_kev.rs', // live KEV mirror: back-fills kev_listed onto vulnerabilities rows
];

// Rust randomness tokens. Written to match real usage/import syntax, not prose — so a
// doc comment mentioning "randomised" or a struct named `brand` does not trip it.
const FORBIDDEN = [
  /\buse\s+rand\b/, //           use rand; / use rand::...
  /\brand\s*::/, //              rand::thread_rng(), rand::random(), rand::Rng
  /\bthread_rng\s*\(/, //        thread_rng()
  /\bgen_range\s*\(/, //         .gen_range(..)
  /\b(StdRng|SmallRng|OsRng|ThreadRng)\b/, // concrete RNG types
  /\bfastrand\s*::/, //          fastrand::...
  /\bgetrandom\s*::/, //         getrandom::...
];

// A reviewed, non-scoring randomness use may opt out with this exact trailing marker.
const ALLOW_MARKER = 'no-rand-gate: allow';

let hits = 0;
for (const rel of FILES) {
  let text;
  try {
    text = readFileSync(rel, 'utf8');
  } catch (e) {
    console.error(`::error file=${rel}::verify_no_rand_in_scoring: cannot read scoped file (${e.code}). If it was renamed/removed, update FILES in scripts/verify_no_rand_in_scoring.mjs.`);
    hits++;
    continue;
  }
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes(ALLOW_MARKER)) continue;
    for (const re of FORBIDDEN) {
      if (re.test(line)) {
        hits++;
        console.error(
          `::error file=${rel},line=${i + 1}::randomness in a scoring/persist module — a persisted finding's score/proof must be deterministic and live-derived. Remove it, or (if genuinely non-scoring and reviewed) append \`// ${ALLOW_MARKER}\`.\n    ${rel}:${i + 1}: ${line.trim()}`,
        );
        break;
      }
    }
  }
}

if (hits > 0) {
  console.error(`\nverify_no_rand_in_scoring: FAILED with ${hits} finding(s).`);
  process.exit(1);
}
console.log(`verify_no_rand_in_scoring: OK — ${FILES.length} scoring/persist modules are randomness-free.`);
