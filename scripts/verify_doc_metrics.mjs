#!/usr/bin/env node
// verify_doc_metrics.mjs — stop headline-metric drift from recurring in docs
// OTHER than docs/METRICS.md.
//
// scripts/sync_doc_metrics.mjs only regenerates / --check's docs/METRICS.md.
// But the same canonical numbers (production engine IDs, real probes, distinct
// implementations, aliases, agent-required, migrations) are restated by hand in
// README.md, AGENTS.md, the inspection runbook/sign-off, and the security &
// compliance doc — and those copies silently drifted (which is exactly what the
// audit kept fixing by hand). This verifier recomputes the canonical values from
// the SAME sources sync_doc_metrics.mjs uses, then asserts each curated doc
// reference still matches. It exits non-zero on any mismatch so CI blocks the drift.
//
//   node scripts/verify_doc_metrics.mjs
//
// Curation rules (keep this map SMALL and robust):
//   * Only gate numbers that are computed live from source below — never a
//     hand-typed constant.
//   * Only gate STABLE metrics. Deliberately NOT gated: the Rust test count
//     (moves on every test added), "Command Center routes" (a UI-audit metric
//     stated as a `≥` target, e.g. "130 (target ≥112)"), and "111/111 pages"
//     (a pass/pass indicator, not a sync_doc_metrics figure).
//   * Anchor each regex on distinctive surrounding text so it cannot capture the
//     wrong number (e.g. "48 agent_required" vs the unrelated "JWT 48 chars").

import { execSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function sh(cmd) {
  return execSync(cmd, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

// Canonical values — computed live from the same sources of truth that
// scripts/sync_doc_metrics.mjs / docs/METRICS.md rely on.
function computeCanonical() {
  const engines = JSON.parse(sh('node scripts/engine_reality_audit.mjs')).production || {};
  const migDir = join('crates', 'weissman-db', 'migrations');
  const migAbs = join(ROOT, migDir);
  const migrations = existsSync(migAbs)
    ? readdirSync(migAbs).filter((f) => f.endsWith('.sql')).length
    : null;
  return {
    total: engines.total ?? null, // production engine IDs
    real_probe: engines.real_probe ?? null,
    distinct: engines.distinct_real_implementations ?? null,
    advisory: engines.advisory_only ?? null,
    alias: engines.alias ?? null,
    agent_required: engines.agent_required ?? null,
    migrations, // crates/weissman-db/migrations *.sql count
  };
}

// Curated map: { file, metric, regex-with-one-capture-group, human label }.
// The regex must capture exactly the stated number in group 1.
const REFS = [
  // AGENTS.md — headline metrics table.
  { file: 'AGENTS.md', metric: 'total', re: /Production engines \| \*\*(\d+)\*\*/, label: 'Production engines' },
  { file: 'AGENTS.md', metric: 'real_probe', re: /Real probes \| \*\*(\d+)\*\*/, label: 'Real probes' },
  { file: 'AGENTS.md', metric: 'agent_required', re: /Agent-required engines \| \*\*(\d+)\*\*/, label: 'Agent-required engines' },

  // README.md — headline sentence + engines breakdown + DB box.
  { file: 'README.md', metric: 'total', re: /\*\*(\d+) production engine IDs\*\*/, label: 'production engine IDs' },
  { file: 'README.md', metric: 'real_probe', re: /\*\*(\d+) real live probes\*\*/, label: 'real live probes' },
  { file: 'README.md', metric: 'distinct', re: /\((\d+) distinct implementations\)/, label: 'distinct implementations' },
  { file: 'README.md', metric: 'alias', re: /\*\*(\d+) aliases\*\* that resolve/, label: 'aliases' },
  { file: 'README.md', metric: 'agent_required', re: /\*\*(\d+) agent-required\*\* host/, label: 'agent-required' },
  { file: 'README.md', metric: 'migrations', re: /•\s*(\d+)\s+migrations/, label: 'migrations (DB box)' },

  // docs/operations/INSPECTION-DAY-RUNBOOK.md — table + taxonomy line.
  { file: 'docs/operations/INSPECTION-DAY-RUNBOOK.md', metric: 'total', re: /Production engines \| \*\*(\d+)\*\*/, label: 'Production engines' },
  { file: 'docs/operations/INSPECTION-DAY-RUNBOOK.md', metric: 'real_probe', re: /\*\*(\d+) real_probe\*\*/, label: 'real_probe' },
  { file: 'docs/operations/INSPECTION-DAY-RUNBOOK.md', metric: 'alias', re: /\*\*(\d+) alias\*\*/, label: 'alias' },
  { file: 'docs/operations/INSPECTION-DAY-RUNBOOK.md', metric: 'agent_required', re: /\*\*(\d+) agent_required\*\*/, label: 'agent_required' },

  // docs/operations/INSPECTION-READY-SIGNOFF.md — table + G4 checklist line.
  { file: 'docs/operations/INSPECTION-READY-SIGNOFF.md', metric: 'total', re: /Production engines \| \*\*(\d+)\*\*/, label: 'Production engines' },
  { file: 'docs/operations/INSPECTION-READY-SIGNOFF.md', metric: 'total', re: /(\d+) engine IDs, 0 gaps/, label: 'G4 wiring engine IDs' },

  // SECURITY_AND_COMPLIANCE.md — metrics table + engine-kinds breakdown.
  { file: 'SECURITY_AND_COMPLIANCE.md', metric: 'total', re: /Production engine IDs \| \*\*(\d+)\*\*/, label: 'Production engine IDs' },
  { file: 'SECURITY_AND_COMPLIANCE.md', metric: 'real_probe', re: /(\d+) real_probe \(/, label: 'real_probe' },
  { file: 'SECURITY_AND_COMPLIANCE.md', metric: 'distinct', re: /\((\d+) distinct impls\)/, label: 'distinct impls' },
  { file: 'SECURITY_AND_COMPLIANCE.md', metric: 'alias', re: /(\d+) alias,/, label: 'alias' },
  { file: 'SECURITY_AND_COMPLIANCE.md', metric: 'agent_required', re: /(\d+) agent_required,/, label: 'agent_required' },

  // Extra gated occurrences the first-match-only version missed (these are exactly the
  // spots that silently drifted to 592 / 563 / "2 advisory-only"). matchAll below
  // asserts EVERY occurrence, so both README engine-ID sentences must agree.
  { file: 'README.md', metric: 'advisory', re: /(\d+) advisory-only/, label: 'advisory-only' },
  { file: 'README.md', metric: 'total', re: /▶ (\d+) engines\b/, label: 'worker→engines diagram' },
  { file: 'AGENTS.md', metric: 'total', re: /(\d+) engine IDs ↔ dispatch/, label: 'engine IDs ↔ dispatch' },
  { file: 'docs/architecture.md', metric: 'total', re: /▶│ (\d+) engines\b/, label: 'engines (diagram)' },
  { file: 'docs/SOC_ENGINES_ARCHITECTURE.md', metric: 'total', re: /\*\*(\d+) entries\*\*/, label: 'PRODUCTION_ENGINE_IDS entries' },
  { file: 'docs/SOC_ENGINES_ARCHITECTURE.md', metric: 'total', re: /all (\d+) engine IDs/, label: 'Engine Matrix engine IDs' },
];

function main() {
  const canonical = computeCanonical();

  // Refuse to "pass" if any canonical value failed to compute — a null here
  // would otherwise make every check trivially fail, or (worse) silently skip.
  const missing = Object.entries(canonical).filter(([, v]) => !Number.isInteger(v));
  if (missing.length) {
    console.error('❌ verify_doc_metrics: could not compute canonical values from source:');
    for (const [k] of missing) console.error(`   - ${k}`);
    console.error('   (is scripts/engine_reality_audit.mjs runnable? are migrations present?)');
    process.exit(2);
  }

  const failures = [];
  let occurrencesChecked = 0;
  for (const ref of REFS) {
    const abs = join(ROOT, ref.file);
    if (!existsSync(abs)) {
      failures.push(`${ref.file}: file not found (curated reference is stale)`);
      continue;
    }
    const text = readFileSync(abs, 'utf8');
    const want = canonical[ref.metric];
    // Assert EVERY occurrence, not just the first. A single doc can restate the same
    // metric more than once (README states the engine count in two sentences plus a
    // diagram), and gating only the first match is exactly how "592"/"563" slipped
    // through before.
    const matches = [...text.matchAll(new RegExp(ref.re.source, 'g'))];
    if (matches.length === 0) {
      failures.push(`${ref.file}: could not locate "${ref.label}" (pattern ${ref.re}); expected ${want}. Re-anchor the curated regex or fix the doc.`);
      continue;
    }
    matches.forEach((m, i) => {
      occurrencesChecked++;
      const got = parseInt(m[1], 10);
      if (got !== want) {
        const which = matches.length > 1 ? ` (occurrence ${i + 1} of ${matches.length})` : '';
        failures.push(`${ref.file}: "${ref.label}"${which} says ${got} but canonical ${ref.metric} = ${want}. Update every occurrence to ${want}.`);
      }
    });
  }

  if (failures.length) {
    console.error('❌ Doc metric drift detected (source of truth: scripts/engine_reality_audit.mjs + migrations):');
    for (const f of failures) console.error(`   • ${f}`);
    console.error('\nCanonical values:', JSON.stringify(canonical));
    console.error('Fix the doc(s) above to the canonical value, or update the curated map in scripts/verify_doc_metrics.mjs if the metric legitimately moved.');
    process.exit(1);
  }

  console.log(`✅ ${occurrencesChecked} doc metric occurrences (${REFS.length} curated references across ${new Set(REFS.map((r) => r.file)).size} docs) match source. Canonical: ${JSON.stringify(canonical)}`);
}

main();
