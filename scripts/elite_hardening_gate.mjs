#!/usr/bin/env node
/**
 * Elite hardening Part 2 gate — asserts the 100-control kernel, Command Center
 * page, API route, and migration exist. Does not change G1–G7 numbering.
 */
import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const fail = (msg) => {
  console.error(`elite_hardening_gate: ${msg}`)
  process.exit(1)
}

const catalog = join(ROOT, 'fingerprint_engine/src/elite_hardening/catalog.rs')
const modRs = join(ROOT, 'fingerprint_engine/src/elite_hardening/mod.rs')
const page = join(ROOT, 'frontend/src/pages/EliteHardeningCommandCenter.jsx')
const routes = join(ROOT, 'fingerprint_engine/src/http/serve_route_groups.rs')
const mig = join(ROOT, 'crates/weissman-db/migrations/20260827170000_elite_hardening_part2.sql')
const migAcl = join(
  ROOT,
  'crates/weissman-db/migrations/20260827194500_elite_hardening_architect_acl.sql',
)
const moat = join(ROOT, 'fingerprint_engine/src/elite_hardening/moat.rs')
const hfv = join(ROOT, 'fingerprint_engine/src/elite_hardening/hack_fix_verify.rs')
const liveness = join(ROOT, 'fingerprint_engine/src/elite_hardening/host_liveness.rs')
const cascade = join(ROOT, 'fingerprint_engine/src/elite_hardening/dns_cascade.rs')

for (const p of [catalog, modRs, page, routes, mig, migAcl, moat, hfv, liveness, cascade]) {
  if (!existsSync(p)) fail(`missing ${p}`)
}

const cat = readFileSync(catalog, 'utf8')
const ids = [...cat.matchAll(/c!\(\s*(\d+)\s*,/g)].map((m) => Number(m[1]))
if (ids.length !== 100) fail(`catalog has ${ids.length} controls, expected 100`)
for (let i = 1; i <= 100; i++) {
  if (ids[i - 1] !== i) fail(`catalog id gap at ${i}`)
}

const snap = readFileSync(modRs, 'utf8')
if (!snap.includes('fn live_status')) fail('live_status missing')
if (!snap.includes('controls_total')) fail('status snapshot missing controls_total')

const pageSrc = readFileSync(page, 'utf8')
if (!pageSrc.includes('/api/elite-hardening/status')) fail('page does not fetch live status API')
if (!pageSrc.includes('EvidenceNotice')) fail('page missing EvidenceNotice')
if (!pageSrc.includes('searchQuery')) fail('page missing search')
if (!pageSrc.includes('moat')) fail('page missing sovereign moat lanes')
if (!pageSrc.includes('hfv')) fail('page missing Hack-Fix-Verify loop')
if (!readFileSync(moat, 'utf8').includes('PRODUCTION_ENGINE_IDS')) fail('moat.rs not live-wired to production engines')
if (!readFileSync(hfv, 'utf8').includes('failed_scan_cannot_close')) fail('hack_fix_verify missing fail-closed rule')
if (!readFileSync(hfv, 'utf8').includes('host_liveness_required_to_close')) {
  fail('hack_fix_verify missing host liveness rule')
}
if (!readFileSync(liveness, 'utf8').includes('agent_host_binds_target')) {
  fail('host_liveness missing per-host agent bind (client_id heartbeat is a false close)')
}
if (!readFileSync(cascade, 'utf8').includes('udp_internal')) fail('dns_cascade missing internal UDP stage')
if (!readFileSync(cascade, 'utf8').includes('dns_dot_udp_downgrade')) {
  fail('dns_cascade missing DoT→UDP critical SOC event')
}
const nlqa = join(ROOT, 'fingerprint_engine/src/elite_hardening/nlqa_chain.rs')
if (!existsSync(nlqa)) fail(`missing ${nlqa}`)
if (!readFileSync(nlqa, 'utf8').includes('nlqa1_audit_fallback')) {
  fail('nlqa1 missing JSON fallback when mPSC is full')
}

const routeSrc = readFileSync(routes, 'utf8')
if (!routeSrc.includes('/api/elite-hardening/status')) fail('API route not registered')

const sql = readFileSync(mig, 'utf8')
if (!sql.includes('finding_candidates')) fail('migration missing finding_candidates')
if (!sql.includes('weissman_ro')) fail('migration missing weissman_ro GRANT')
if (!sql.includes('public.app_current_tenant_id()')) {
  fail('elite RLS must use app_current_tenant_id() (empty GUC must not cast to bigint)')
}
if (sql.includes("current_setting('app.current_tenant_id', true)::bigint")) {
  fail('elite RLS reintroduced raw tenant GUC ::bigint (worker empty-scope crash)')
}

const sqlAcl = readFileSync(migAcl, 'utf8')
if (!sqlAcl.includes('insert_supreme_council_memory')) fail('ACL migration missing definer insert')
if (!sqlAcl.includes('nl_query_audit')) fail('ACL migration missing nlqa hash columns')
if (!sqlAcl.includes('supreme_council_memory_acl')) fail('ACL migration missing council trigger')

console.log('elite_hardening_gate: 100 controls, live API, page, migration — ok')
