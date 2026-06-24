#!/usr/bin/env node
/**
 * Verifies cloud_posture CNAPP catalog parity across backend + frontend.
 * Exit 0 = complete; exit 1 = gaps found.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const engineRs = fs.readFileSync(
  path.join(root, 'fingerprint_engine/src/cloud_posture_engine.rs'),
  'utf8',
)
const uiJsx = fs.readFileSync(
  path.join(root, 'frontend/src/pages/CloudPostureCommandCenter.jsx'),
  'utf8',
)

const planesMatch = engineRs.match(
  /pub const CNAPP_SERVICE_PLANES: &\[&str\] = &\[([\s\S]*?)\];/,
)
if (!planesMatch) {
  console.error('FAIL: CNAPP_SERVICE_PLANES not found in cloud_posture_engine.rs')
  process.exit(1)
}
const planes = [...planesMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
const planeCountMatch = engineRs.match(/pub const CNAPP_PLANE_COUNT: usize = (\d+);/)
const planeCount = planeCountMatch ? Number(planeCountMatch[1]) : 0

const uiServices = [...uiJsx.matchAll(/service: '([^']+)'/g)].map((m) => m[1])
const uiChecks = [...uiJsx.matchAll(/key: '(check_[^']+)'/g)].map((m) => m[1])

const dispatchHits = new Set()
for (const p of planes) {
  if (engineRs.includes(`opts.wants("${p}")`)) dispatchHits.add(p)
}
// vpc scans via ec2||vpc branch
if (engineRs.includes('opts.wants("ec2") || opts.wants("vpc")')) dispatchHits.add('vpc')

const missingDispatch = planes.filter((p) => !dispatchHits.has(p))
const uiMissingFromCatalog = planes.filter(
  (p) => p !== 'vpc' && !uiServices.includes(p),
)
const catalogOnlyUi = uiServices.filter((s) => !planes.includes(s))

const requiredChecks = [
  'check_s3_object_lock',
  'check_neptune',
  'check_memorydb',
  'check_backup',
  'check_organizations',
  'check_sfn',
  'check_sso',
]
const missingChecks = requiredChecks.filter((c) => !uiChecks.includes(c))

let failed = false
const report = (ok, msg) => {
  console.log(`${ok ? 'OK' : 'FAIL'}: ${msg}`)
  if (!ok) failed = true
}

report(planes.length === planeCount, `plane array length ${planes.length} == CNAPP_PLANE_COUNT ${planeCount}`)
report(missingDispatch.length === 0, `dispatch wired for all planes (${missingDispatch.length} missing: ${missingDispatch.join(', ') || 'none'})`)
report(uiMissingFromCatalog.length === 0, `UI service toggles cover catalog (${uiMissingFromCatalog.join(', ') || 'all covered'})`)
report(catalogOnlyUi.length === 0, `no orphan UI services (${catalogOnlyUi.join(', ') || 'none'})`)
report(missingChecks.length === 0, `UI check toggles for final planes (${missingChecks.join(', ') || 'all present'})`)
report(engineRs.includes('"catalog_status": "complete"'), 'cnapp_catalog_status marks complete')
report(engineRs.includes('cnapp_risk_register'), 'CNAPP risk register in summary')
report(engineRs.includes('synthesize_graph_attack_paths'), '2-hop graph attack paths')
report(engineRs.includes('synthesize_attack_paths'), 'toxic combination engine')

console.log('\nPlanes:', planes.join(', '))
console.log('UI services:', uiServices.length)
console.log('UI checks:', uiChecks.length)

process.exit(failed ? 1 : 0)
