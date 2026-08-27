// Engine reality audit — derives, directly from source, exactly what each catalog engine ID is:
//   real_probe       : canonical engine with a live dispatch arm (real network/host I/O)
//   alias            : retag that resolves to another canonical engine (same detection logic)
//   agent_required   : remote-impossible; queued on endpoint_agent_tasks until an agent is online
//   special          : poe_synthesis (routed via the async job path, not the dispatch match)
//   no_path          : in the catalog but with no execution path (should be ZERO; CI-gated)
//
// It also maps every dispatch arm to its implementation function so duplicate IDs sharing one
// implementation (delegates) are counted precisely. No estimates — everything is parsed from code.
//
// Classification is shared with engine_coverage_accuracy_report.mjs via scripts/lib/engine_reality.mjs
// so the reality gate and the coverage/accuracy proof can never disagree.

import path from 'node:path'
import { loadEngineReality } from './lib/engine_reality.mjs'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const reality = await loadEngineReality(root)
const { productionIds, frontendIds, resolveMap, criticalInfraIds, implFor, tally } = reality

const prod = tally(productionIds)
const fe = tally(frontendIds)

// Distinct real implementations behind the real_probe IDs (delegates share one impl fn).
const implCount = new Map()
for (const id of prod.real_probe) {
  const impl = criticalInfraIds.has(id) ? 'critical_infra::dispatch' : implFor(id)
  implCount.set(impl, (implCount.get(impl) || 0) + 1)
}
const distinctImpls = implCount.size
const sharedImpls = [...implCount.entries()]
  .filter(([, n]) => n > 1)
  .sort((a, b) => b[1] - a[1])

// Which canonical engines absorb the most aliases.
const aliasByCanonical = new Map()
for (const id of prod.alias) {
  const canon = resolveMap.get(id)
  aliasByCanonical.set(canon, (aliasByCanonical.get(canon) || 0) + 1)
}
const topAliasCanonicals = [...aliasByCanonical.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)

const out = {
  production: {
    total: productionIds.length,
    real_probe: prod.real_probe.length,
    distinct_real_implementations: distinctImpls,
    alias: prod.alias.length,
    agent_required: prod.agent_required.length,
    special: prod.special.length,
    no_path: prod.no_path.length,
  },
  frontend_catalog: {
    total: frontendIds.length,
    real_probe: fe.real_probe.length,
    alias: fe.alias.length,
    agent_required: fe.agent_required.length,
    special: fe.special.length,
    no_path: fe.no_path.length,
  },
  delegates_sharing_one_impl: sharedImpls.slice(0, 20).map(([impl, n]) => ({ impl, ids: n })),
  delegate_id_count: sharedImpls.reduce((s, [, n]) => s + (n - 1), 0),
  top_alias_absorbers: topAliasCanonicals.map(([canon, n]) => ({ canonical: canon, aliases: n })),
  agent_required_ids: [...reality.agentRequired].filter((id) => productionIds.includes(id)).sort(),
  no_path_ids: prod.no_path,
}

console.log(JSON.stringify(out, null, 2))

if (prod.no_path.length > 0) {
  process.exit(1)
}
