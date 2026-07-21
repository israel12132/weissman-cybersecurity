#!/usr/bin/env node
/**
 * Generate the vendored MITRE ATT&CK technique index used by the coverage gate.
 *
 * The coverage report and its CI gate must be HERMETIC — they cannot fetch ~60 MB of STIX at
 * build time. So we vendor a compact, authoritative index built once from the official MITRE
 * ATT&CK STIX bundles (Enterprise + Mobile + ICS — the three domains this platform covers), and
 * refresh it with this script when a new ATT&CK release lands. The gate reads only the committed
 * index.
 *
 * The index also records `revoked_by` (old technique id -> the id MITRE replaced it with), so the
 * gate can flag a stale mapping AND tell you exactly what to change it to.
 *
 * Usage:
 *   # from local STIX bundles (recommended — reproducible):
 *   node scripts/generate_attack_index.mjs enterprise-attack.json mobile-attack.json ics-attack.json
 *
 *   # or fetch the current releases directly from MITRE:
 *   node scripts/generate_attack_index.mjs --fetch
 *
 * Writes scripts/data/attack_technique_index.json.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT = path.join(ROOT, 'scripts/data/attack_technique_index.json')
const BASE = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master'
const DOMAINS = [
  { key: 'enterprise', url: `${BASE}/enterprise-attack/enterprise-attack.json` },
  { key: 'mobile', url: `${BASE}/mobile-attack/mobile-attack.json` },
  { key: 'ics', url: `${BASE}/ics-attack/ics-attack.json` },
]

function externalId(o) {
  const ref = (o.external_references || []).find((r) => r.source_name === 'mitre-attack')
  return ref?.external_id || null
}

async function loadBundles() {
  const paths = process.argv.slice(2).filter((a) => !a.startsWith('--'))
  if (paths.length) {
    // Match each provided path to a domain by filename.
    return DOMAINS.map((d) => {
      const p = paths.find((x) => x.includes(d.key))
      if (!p) throw new Error(`no bundle path matching "${d.key}" among: ${paths.join(', ')}`)
      return { key: d.key, bundle: JSON.parse(fs.readFileSync(p, 'utf8')) }
    })
  }
  if (process.argv.includes('--fetch')) {
    return Promise.all(
      DOMAINS.map(async (d) => {
        process.stderr.write(`fetching ${d.url} ...\n`)
        const r = await fetch(d.url)
        if (!r.ok) throw new Error(`fetch ${d.key} failed: HTTP ${r.status}`)
        return { key: d.key, bundle: await r.json() }
      }),
    )
  }
  throw new Error('provide STIX bundle paths (enterprise/mobile/ics), or pass --fetch')
}

const loaded = await loadBundles()

const techniques = {}
const revokedById = {} // stix id -> external_id (for resolving revoked-by targets)
const revokedRelations = [] // { source: stixId, target: stixId }
const tacticsOrder = []
const tacticNames = {}
const tacticDomain = {}
const tacticTotals = {}
const versions = {}

for (const { key, bundle } of loaded) {
  const objects = bundle.objects || []

  const collection = objects.find((o) => o.type === 'x-mitre-collection' && o.x_mitre_version)
  if (collection) versions[key] = collection.x_mitre_version

  // Tactics in matrix order, namespaced by domain so Enterprise/Mobile/ICS don't collide.
  const tacticObjs = objects.filter(
    (o) => o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated,
  )
  const shortByRef = new Map(tacticObjs.map((t) => [t.id, t.x_mitre_shortname]))
  const nameByShort = new Map(tacticObjs.map((t) => [t.x_mitre_shortname, t.name]))
  // A bundle can carry more than one matrix (e.g. Mobile ships "Mobile ATT&CK" plus the legacy
  // "Network-Based Effects"). Union every non-revoked matrix's tactics, in order, deduped.
  const matrices = objects.filter((o) => o.type === 'x-mitre-matrix' && !o.revoked)
  for (const matrix of matrices) {
    for (const ref of matrix.tactic_refs || []) {
      const short = shortByRef.get(ref)
      if (!short) continue
      const nsKey = `${key}:${short}`
      if (nsKey in tacticTotals) continue
      tacticsOrder.push(nsKey)
      tacticNames[nsKey] = nameByShort.get(short) || short
      tacticDomain[nsKey] = key
      tacticTotals[nsKey] = 0
    }
  }

  for (const o of objects) {
    if (o.type === 'relationship' && o.relationship_type === 'revoked-by') {
      revokedRelations.push({ source: o.source_ref, target: o.target_ref })
    }
    if (o.type !== 'attack-pattern') continue
    const id = externalId(o)
    if (!id) continue
    if (o.revoked || o.x_mitre_deprecated) {
      revokedById[o.id] = id
      continue
    }
    const tactics = (o.kill_chain_phases || [])
      .filter((p) => p.kill_chain_name.startsWith('mitre'))
      .map((p) => `${key}:${p.phase_name}`)
    techniques[id] = {
      name: o.name,
      domain: key,
      tactics,
      sub: Boolean(o.x_mitre_is_subtechnique),
    }
    for (const t of tactics) if (t in tacticTotals) tacticTotals[t] += 1
  }

  // Record external_id for revoked source objects too (they live in revokedById already).
  for (const o of objects) {
    if (o.type === 'attack-pattern' && (o.revoked || o.x_mitre_deprecated)) {
      revokedById[o.id] = externalId(o)
    }
  }
}

// Build revoked external_id -> replacement external_id, resolving stix refs.
// Need the replacement's external_id even when the target is a live (non-revoked) technique.
const externalByStix = {}
for (const { bundle } of loaded) {
  for (const o of bundle.objects || []) {
    if (o.type === 'attack-pattern') externalByStix[o.id] = externalId(o)
  }
}
const revokedBy = {}
for (const { source, target } of revokedRelations) {
  const oldId = externalByStix[source]
  const newId = externalByStix[target]
  if (oldId && newId && !techniques[oldId]) revokedBy[oldId] = newId
}

const index = {
  source: 'MITRE ATT&CK (mitre-attack/attack-stix-data) — Enterprise + Mobile + ICS',
  attack_versions: versions,
  generated_by: 'scripts/generate_attack_index.mjs',
  tactics_order: tacticsOrder,
  tactic_names: tacticNames,
  tactic_domain: tacticDomain,
  tactic_totals: tacticTotals,
  technique_count: Object.keys(techniques).length,
  revoked_count: Object.keys(revokedBy).length,
  revoked_by: revokedBy,
  techniques,
}

fs.mkdirSync(path.dirname(OUT), { recursive: true })
fs.writeFileSync(OUT, `${JSON.stringify(index, null, 2)}\n`)
process.stderr.write(
  `wrote ${path.relative(ROOT, OUT)} — versions ${JSON.stringify(versions)}, ${index.technique_count} techniques, ${tacticsOrder.length} tactics, ${index.revoked_count} revoked mappings\n`,
)
