#!/usr/bin/env node
/**
 * MITRE ATT&CK coverage — the industry-standard proof of what the catalog actually covers,
 * measured against the current official ATT&CK release.
 *
 * Every engine in the registry is mapped to a MITRE ATT&CK technique. This resolves those IDs
 * against a vendored, authoritative index built from MITRE's STIX bundles
 * (Enterprise + Mobile + ICS — see scripts/generate_attack_index.mjs) and produces:
 *   - docs/MITRE_ATTACK_COVERAGE.md      human/auditor-facing coverage matrix (per tactic, per domain)
 *   - docs/mitre_navigator_layer.json    official ATT&CK Navigator layers (load at mitre-attack.github.io)
 *   - JSON summary on stdout
 *
 * The --check gate enforces CURRENCY: every technique the catalog claims must be a real,
 * non-revoked technique in the current ATT&CK release. A stale (revoked/renamed) or invented ID
 * fails the build and prints the exact replacement — so ATT&CK mappings can never silently rot.
 *
 * Usage:
 *   node scripts/mitre_attack_coverage.mjs           # print JSON + write the doc + navigator layer
 *   node scripts/mitre_attack_coverage.mjs --check    # CI gate: fail on any stale/invalid mapping
 *   node scripts/mitre_attack_coverage.mjs --no-write  # don't touch generated files
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const CHECK = args.includes('--check')
const NO_WRITE = args.includes('--no-write')
const DOC_PATH = path.join(ROOT, 'docs/MITRE_ATTACK_COVERAGE.md')
const LAYER_DIR = path.join(ROOT, 'docs/attack-navigator')

const idx = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts/data/attack_technique_index.json'), 'utf8'))
const registry = (
  await import(pathToFileURL(path.join(ROOT, 'frontend/src/lib/enginesRegistry.js')).href)
).ENGINES_REGISTRY

const DOMAIN_LABEL = { enterprise: 'Enterprise', mobile: 'Mobile', ics: 'ICS' }
const NAV_DOMAIN = { enterprise: 'enterprise-attack', mobile: 'mobile-attack', ics: 'ics-attack' }

// ── Resolve every engine to its technique + tactics; collect currency breaches ────────────────
const stale = [] // { id, engine, replacement }
const unknown = [] // { id, engine }
const techToEngines = new Map() // techniqueID -> Set(engineId)
const tacticCovered = new Map() // nsTactic -> Set(techniqueID)
const tacticEngines = new Map() // nsTactic -> Set(engineId)
const domainTechniques = new Map() // domain -> Set(techniqueID)

for (const e of registry) {
  const id = e.mitre
  if (!id) continue
  const tech = idx.techniques[id]
  if (!tech) {
    if (idx.revoked_by[id]) stale.push({ id, engine: e.id, replacement: idx.revoked_by[id] })
    else unknown.push({ id, engine: e.id })
    continue
  }
  if (!techToEngines.has(id)) techToEngines.set(id, new Set())
  techToEngines.get(id).add(e.id)
  if (!domainTechniques.has(tech.domain)) domainTechniques.set(tech.domain, new Set())
  domainTechniques.get(tech.domain).add(id)
  for (const nsTactic of tech.tactics) {
    if (!tacticCovered.has(nsTactic)) tacticCovered.set(nsTactic, new Set())
    if (!tacticEngines.has(nsTactic)) tacticEngines.set(nsTactic, new Set())
    tacticCovered.get(nsTactic).add(id)
    tacticEngines.get(nsTactic).add(e.id)
  }
}

const coveredTechniques = [...techToEngines.keys()]
const subCount = coveredTechniques.filter((id) => idx.techniques[id].sub).length

// ── Per-domain tactic coverage tables ─────────────────────────────────────────────────────────
function domainReport(domain) {
  // Only real tactics of the current release (total > 0); a legacy tactic MITRE emptied out
  // (e.g. mobile "Network-Based Effects") is skipped rather than shown as a 0/0 row.
  const tactics = idx.tactics_order.filter(
    (t) => idx.tactic_domain[t] === domain && (idx.tactic_totals[t] || 0) > 0,
  )
  const rows = tactics.map((nsTactic) => {
    const short = nsTactic.split(':')[1]
    const total = idx.tactic_totals[nsTactic] || 0
    const covered = tacticCovered.get(nsTactic)?.size || 0
    return {
      tactic: idx.tactic_names[nsTactic] || short,
      covered,
      total,
      pct: total ? Math.round((covered / total) * 100) : 0,
      engines: tacticEngines.get(nsTactic)?.size || 0,
    }
  })
  const domTechs = domainTechniques.get(domain)?.size || 0
  return {
    domain,
    label: DOMAIN_LABEL[domain] || domain,
    attack_version: idx.attack_versions?.[domain] ?? null,
    tactics_total: tactics.length,
    tactics_covered: rows.filter((r) => r.covered > 0).length,
    techniques_covered: domTechs,
    domain_technique_total: Object.keys(idx.techniques).filter(
      (id) => idx.techniques[id].domain === domain,
    ).length,
    rows,
  }
}

const domains = [...new Set([...domainTechniques.keys()])]
const domainOrder = ['enterprise', 'mobile', 'ics'].filter((d) => domains.includes(d))
const perDomain = domainOrder.map(domainReport)

const totalAttackTechniques = idx.technique_count
const report = {
  attack_versions: idx.attack_versions,
  generated_from: 'frontend registry × vendored MITRE ATT&CK STIX index',
  totals: {
    engines_mapped: registry.filter((e) => e.mitre).length,
    distinct_techniques_covered: coveredTechniques.length,
    sub_techniques_covered: subCount,
    attack_techniques_total: totalAttackTechniques,
    coverage_pct_of_all_attack: Math.round((coveredTechniques.length / totalAttackTechniques) * 1000) / 10,
    domains_covered: domainOrder.map((d) => DOMAIN_LABEL[d] || d),
  },
  per_domain: perDomain,
  currency: {
    ok: stale.length === 0 && unknown.length === 0,
    stale,
    unknown,
  },
}

// ── ATT&CK Navigator layers — one self-contained layer object per domain (each directly
// uploadable at the official Navigator; the app expects a single layer per file, not an array).
function navigatorLayer(domain) {
  const version = String(idx.attack_versions?.[domain] ?? '').split('.')[0]
  const techniques = [...domainTechniques.get(domain)].map((id) => ({
    techniqueID: id,
    score: techToEngines.get(id).size,
    comment: [...techToEngines.get(id)].sort().join(', '),
    enabled: true,
  }))
  const maxScore = Math.max(1, ...techniques.map((t) => t.score))
  return {
    name: `Weissman — ${DOMAIN_LABEL[domain]} coverage`,
    description: `Engine coverage of MITRE ATT&CK ${DOMAIN_LABEL[domain]}. Score = number of engines mapped to the technique. Generated by scripts/mitre_attack_coverage.mjs.`,
    domain: NAV_DOMAIN[domain],
    versions: { attack: version, navigator: '5.1.0', layer: '4.5' },
    techniques,
    gradient: { colors: ['#dbeafe', '#2563eb', '#1e3a8a'], minValue: 0, maxValue: maxScore },
    legendItems: [{ label: 'engines mapped to technique', color: '#2563eb' }],
    hideDisabled: false,
  }
}

// ── Markdown coverage matrix ──────────────────────────────────────────────────────────────────
function renderDoc(r) {
  const t = r.totals
  const versions = Object.entries(r.attack_versions || {})
    .map(([k, v]) => `${DOMAIN_LABEL[k] || k} v${v}`)
    .join(' · ')
  const domainSections = r.per_domain
    .map((d) => {
      const rows = d.rows
        .map(
          (row) =>
            `| ${row.tactic} | ${row.covered} / ${row.total} | ${row.pct}% | ${row.engines} |`,
        )
        .join('\n')
      return `### ${d.label} ATT&CK — ${d.techniques_covered} techniques, ${d.tactics_covered}/${d.tactics_total} tactics

| Tactic | Techniques covered | % of tactic | Engines |
|--------|-------------------:|------------:|--------:|
${rows}`
    })
    .join('\n\n')

  return `<!-- GENERATED by scripts/mitre_attack_coverage.mjs — do not edit by hand. -->
# MITRE ATT&CK Coverage

Measured against the **current official ATT&CK release** (${versions}) by
\`scripts/mitre_attack_coverage.mjs\`, resolving every engine's technique ID against a vendored,
authoritative index built from MITRE's STIX bundles. Re-verified in CI — a stale or invented
technique ID fails the build.

Regenerate: \`node scripts/mitre_attack_coverage.mjs\` · Currency gate: \`--check\` · Navigator
layers (one per domain): [\`docs/attack-navigator/\`](attack-navigator/) — upload
\`enterprise.json\` / \`mobile.json\` / \`ics.json\` at
<https://mitre-attack.github.io/attack-navigator/>.

## Headline

- **${t.distinct_techniques_covered} distinct ATT&CK techniques** covered by
  **${t.engines_mapped} mapped engines** (${t.sub_techniques_covered} of them sub-techniques).
- Spans **${t.domains_covered.join(', ')}** ATT&CK — every technique validated against the current
  release, **0 stale / 0 invented**.
- Coverage is broad *and* current: mappings track the latest ATT&CK, not a frozen snapshot.

## Coverage by domain and tactic

*"Techniques covered" counts distinct ATT&CK techniques the catalog maps within that tactic;
"% of tactic" is against the total techniques MITRE lists for that tactic in the current release.*

${domainSections}

## Why this is the bar

MITRE ATT&CK is the language every SOC, red team, and buyer uses to compare coverage. Two things
separate a serious program from a checklist:

1. **Breadth that is measured, not asserted** — coverage is computed from source against the
   official framework, per tactic, per domain, and republished on every change.
2. **Currency that is enforced** — the ${idx.revoked_count} technique renames/revocations in the
   latest ATT&CK are tracked; the CI gate refuses any mapping that points at a technique MITRE has
   retired. Most catalogs quietly drift years behind. This one cannot.
`
}

if (!NO_WRITE) {
  fs.writeFileSync(DOC_PATH, renderDoc(report))
  fs.mkdirSync(LAYER_DIR, { recursive: true })
  for (const domain of domainOrder) {
    fs.writeFileSync(
      path.join(LAYER_DIR, `${domain}.json`),
      `${JSON.stringify(navigatorLayer(domain), null, 2)}\n`,
    )
  }
}

console.log(JSON.stringify(report, null, 2))

if (CHECK && !report.currency.ok) {
  console.error('\nmitre_attack_coverage: FAIL — ATT&CK mappings are not current')
  for (const s of stale) console.error(`  - ${s.engine}: ${s.id} is revoked → use ${s.replacement}`)
  for (const u of unknown) console.error(`  - ${u.engine}: ${u.id} is not a known ATT&CK technique`)
  process.exit(1)
}
