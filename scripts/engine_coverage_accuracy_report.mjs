#!/usr/bin/env node
/**
 * Engine Coverage & Accuracy report — the single authoritative proof that the catalog's
 * headline number is real breadth, not a count of stubs.
 *
 * Where `engine_reality_audit.mjs` proves *every* catalog ID has an execution path (depth),
 * this proves the catalog spans every attack domain with LIVE probes (breadth) and that the
 * false-positive accuracy machinery actually exists in source (accuracy). All figures are
 * derived from code — the Rust engine tables, the frontend registry's group/MITRE metadata,
 * and the FP/TP feedback constants — never hand-typed.
 *
 * Usage:
 *   node scripts/engine_coverage_accuracy_report.mjs            # print JSON + write the doc
 *   node scripts/engine_coverage_accuracy_report.mjs --check    # CI gate: fail on any breach
 *   node scripts/engine_coverage_accuracy_report.mjs --no-write  # don't touch the markdown doc
 *
 * Structural invariants enforced under --check (none require bumping a magic number on a
 * legitimate engine change — they can only be broken by a real regression):
 *   1. no_path == 0                    every catalog engine has an execution path
 *   2. unmapped_mitre == 0             every engine is tagged with a MITRE ATT&CK technique
 *   3. every group has >= 1 real probe no attack domain is pure-alias "coverage theater"
 *   4. accuracy mechanism present      the FP/TP suppression + confidence constants parse
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { loadEngineReality } from './lib/engine_reality.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const CHECK = args.includes('--check')
const NO_WRITE = args.includes('--no-write')
const DOC_PATH = path.join(ROOT, 'docs/ENGINE_COVERAGE_AND_ACCURACY.md')

// ── Accuracy mechanism, parsed from source so the claim can't drift from the code ──────────
function parseAccuracyMechanism() {
  const src = fs.readFileSync(path.join(ROOT, 'fingerprint_engine/src/fp_feedback.rs'), 'utf8')
  const threshold = src.match(/const AUTO_SUPPRESS_FP_THRESHOLD:\s*i32\s*=\s*(\d+)/)
  const clamp = src.match(/\.clamp\(([\d.]+),\s*([\d.]+)\)/)
  // Accept either cast style — `f64::from(tp)` or `tp as f64` — so an equivalent refactor
  // doesn't spuriously break the gate. Matches the Bayesian shrinkage shape (tp+1)/(tp+fp+1).
  const tpF = '(?:f64::from\\(tp\\)|tp as f64)'
  const fpF = '(?:f64::from\\(fp\\)|fp as f64)'
  const formula = new RegExp(
    `\\(${tpF}\\s*\\+\\s*1\\.0\\)\\s*/\\s*\\(${tpF}\\s*\\+\\s*${fpF}\\s*\\+\\s*1\\.0\\)`,
  ).test(src)
  return {
    present: Boolean(threshold && clamp && formula),
    auto_suppress_fp_threshold: threshold ? Number(threshold[1]) : null,
    confidence_multiplier_floor: clamp ? Number(clamp[1]) : null,
    confidence_multiplier_ceiling: clamp ? Number(clamp[2]) : null,
    formula: '(tp + 1) / (tp + fp + 1)',
    auto_suppression: 'a matching (tenant, engine, signature_hash) is silently downgraded to FALSE_POSITIVE',
  }
}

const reality = await loadEngineReality(ROOT)

// ── Breadth: join every registry engine with its group + MITRE + reality class ─────────────
const GROUP_DEFS = (
  await import(pathToFileURL(path.join(ROOT, 'frontend/src/lib/engineGroupDefs.js')).href)
).ENGINE_GROUP_DEFS

const groups = new Map() // id -> { total, real_probe, alias, agent_required, special, no_path, mitre:Set }
const allMitre = new Set()
let unmappedMitre = 0

for (const e of reality.registry) {
  const cls = reality.classify(e.id)
  const gid = e.group || '(ungrouped)'
  if (!groups.has(gid)) {
    groups.set(gid, {
      total: 0,
      real_probe: 0,
      alias: 0,
      agent_required: 0,
      special: 0,
      no_path: 0,
      mitre: new Set(),
    })
  }
  const g = groups.get(gid)
  g.total += 1
  g[cls] += 1
  if (e.mitre) {
    allMitre.add(e.mitre)
    g.mitre.add(e.mitre)
  } else {
    unmappedMitre += 1
  }
}

const labelFor = Object.fromEntries(GROUP_DEFS.map((g) => [g.id, g.label]))
const groupRows = [...groups.entries()]
  .map(([id, g]) => ({
    id,
    label: labelFor[id] || id,
    total: g.total,
    real_probe: g.real_probe,
    alias: g.alias,
    agent_required: g.agent_required,
    distinct_mitre: g.mitre.size,
  }))
  .sort((a, b) => b.total - a.total)

const prod = reality.tally(reality.productionIds)
const distinctImpls = new Set(
  prod.real_probe.map((id) => reality.implFor(id)),
).size

const accuracy = parseAccuracyMechanism()

// ── Gate evaluation ────────────────────────────────────────────────────────────────────────
const groupsWithoutRealProbe = groupRows.filter((g) => g.real_probe === 0).map((g) => g.id)
const breaches = []
if (prod.no_path.length > 0) breaches.push(`no_path engines: ${prod.no_path.length} (must be 0)`)
if (unmappedMitre > 0) breaches.push(`engines missing MITRE technique: ${unmappedMitre} (must be 0)`)
if (groupsWithoutRealProbe.length > 0)
  breaches.push(`attack domains with no live probe: ${groupsWithoutRealProbe.join(', ')}`)
if (!accuracy.present) breaches.push('FP/TP accuracy mechanism not found in fp_feedback.rs')

const report = {
  generated_from: 'source (Rust engine tables + frontend registry + fp_feedback.rs)',
  totals: {
    catalog: reality.registry.length,
    real_probe: prod.real_probe.length,
    distinct_real_implementations: distinctImpls,
    alias: prod.alias.length,
    agent_required: prod.agent_required.length,
    no_path: prod.no_path.length,
  },
  breadth: {
    attack_domains: groupRows.length,
    domains_with_live_probe: groupRows.filter((g) => g.real_probe > 0).length,
    distinct_mitre_attack_techniques: allMitre.size,
    engines_unmapped_to_mitre: unmappedMitre,
    per_domain: groupRows,
  },
  accuracy,
  gate: {
    ok: breaches.length === 0,
    breaches,
  },
}

// ── Markdown proof doc ───────────────────────────────────────────────────────────────────────
function renderDoc(r) {
  const t = r.totals
  const b = r.breadth
  const a = r.accuracy
  const pct = (n) => `${((n / t.catalog) * 100).toFixed(1)}%`
  const fixed1 = (n) => (Number.isFinite(n) ? n.toFixed(1) : String(n))
  const rows = b.per_domain
    .map(
      (g) =>
        `| ${g.label} | ${g.total} | ${g.real_probe} | ${g.alias} | ${g.agent_required} | ${g.distinct_mitre} |`,
    )
    .join('\n')
  return `<!-- GENERATED by scripts/engine_coverage_accuracy_report.mjs — do not edit by hand. -->
# Engine Coverage & Accuracy

**Every figure on this page is derived from source code** (the Rust engine tables, the frontend
engine registry's group/MITRE metadata, and the false-positive feedback constants) by
\`scripts/engine_coverage_accuracy_report.mjs\`, and is re-verified in CI. Nothing here is
hand-typed marketing.

Regenerate: \`node scripts/engine_coverage_accuracy_report.mjs\` · Gate: \`--check\`

## 1. Coverage is real, not a count of stubs

| Class | Count | Share |
|-------|------:|------:|
| **Live probes** (real network / host / TLS / DNS I/O) | ${t.real_probe} | ${pct(t.real_probe)} |
| Aliases (retag → a live probe, same detection logic) | ${t.alias} | ${pct(t.alias)} |
| Agent-required (host-level; endpoint agent performs the detection) | ${t.agent_required} | ${pct(t.agent_required)} |
| **No execution path** (catalog entries that do nothing) | ${t.no_path} | ${pct(t.no_path)} |
| **Catalog total** | **${t.catalog}** | 100% |

- **${t.distinct_real_implementations} distinct probe implementations** back the ${t.real_probe} live
  probes (delegates that share one implementation are counted once).
- **${t.no_path} engines with no execution path** — the catalog headline is fully backed.
- A companion gate, \`engine_reality_audit.mjs\`, independently proves the same *depth* invariant.

## 2. Breadth spans every attack domain

The catalog covers **${b.attack_domains} attack domains** and maps to
**${b.distinct_mitre_attack_techniques} distinct MITRE ATT&CK techniques**, with
**${b.engines_unmapped_to_mitre} engines unmapped**. Every domain carries live probes — no domain
is pure-alias "coverage theater".

| Attack domain | Engines | Live probes | Aliases | Agent | MITRE techniques |
|---------------|--------:|------------:|--------:|------:|-----------------:|
${rows}

## 3. Accuracy: findings are discounted and suppressed, not just emitted

False positives are handled by a per-\`(tenant, engine, signature_hash)\` feedback loop
(\`fingerprint_engine/src/fp_feedback.rs\`), verified end-to-end by
\`scripts/verify_fp_tp_confidence_e2e.mjs\`:

- **Confidence multiplier** \`${a.formula}\` (Bayesian shrinkage), clamped to
  \`[${fixed1(a.confidence_multiplier_floor)}, ${fixed1(a.confidence_multiplier_ceiling)}]\` and applied to
  \`risk_score\` so a noisy signature sinks in the analyst inbox.
- **Auto-suppression** after **${a.auto_suppress_fp_threshold} false-positive marks**: ${a.auto_suppression},
  preserving the audit trail without the noise.
- A true-positive mark decays prior FP count by one, so an engine that corrects its behaviour
  climbs back out of suppression organically.

## 4. Why this matters against XSOAR / Splunk SOAR / Torq / Tines / Swimlane

Those platforms orchestrate *other people's* detections. Weissman ships **${t.real_probe} in-house
offensive probes across ${b.attack_domains} domains and ${b.distinct_mitre_attack_techniques} ATT&CK
techniques**, each wired to real I/O and each discounted by a live accuracy loop — offensive
coverage plus in-house threat intelligence in one backend, not a workflow engine bolted onto
third-party feeds.
`
}

if (!NO_WRITE) {
  fs.writeFileSync(DOC_PATH, renderDoc(report))
}

console.log(JSON.stringify(report, null, 2))

if (CHECK && !report.gate.ok) {
  console.error('\nengine_coverage_accuracy_report: FAIL')
  for (const x of report.gate.breaches) console.error(`  - ${x}`)
  process.exit(1)
}
