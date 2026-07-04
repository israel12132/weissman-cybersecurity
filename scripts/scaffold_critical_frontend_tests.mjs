#!/usr/bin/env node
/** Scaffold missing frontend unit tests (no source patches). */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const fe = path.join(root, 'frontend/src')

const specs = [
  ['lib/clientTarget.test.js', `import { describe, it, expect } from 'vitest'
import { clientPrimaryTargetUrl, resolveClient, engineRunsWithoutTarget } from './clientTarget.js'
describe('clientTarget', () => {
  it('builds https URL', () => {
    expect(clientPrimaryTargetUrl({ domains: '["example.com"]' })).toBe('https://example.com')
  })
  it('resolveClient', () => {
    expect(resolveClient('1', [{ id: 1 }])).toMatchObject({ id: 1 })
  })
  it('targetless engines', () => {
    expect(engineRunsWithoutTarget('zero_day_radar')).toBe(true)
  })
})`],
  ['lib/pdfExport.test.js', `import { describe, it, expect } from 'vitest'
import { buildSimpleTextPdf } from './pdfExport.js'
describe('pdfExport', () => {
  it('PDF magic', () => {
    const b = buildSimpleTextPdf(['Evidence'])
    expect(new TextDecoder().decode(b.slice(0, 8))).toBe('%PDF-1.4')
  })
})`],
  ['lib/apiError.test.js', `import { describe, it, expect } from 'vitest'
import { formatApiErrorFromBody } from './apiError.js'
describe('apiError', () => {
  it('detail string', () => expect(formatApiErrorFromBody({ detail: 'x' }, 400)).toBe('x'))
  it('status fallback', () => expect(formatApiErrorFromBody(null, 502)).toContain('502'))
})`],
  ['lib/aliasClient.test.js', `import { describe, it, expect } from 'vitest'
import { withClientId } from './aliasClient.js'
describe('aliasClient', () => {
  it('query param', () => expect(withClientId('/a', 1)).toBe('/a?client_id=1'))
})`],
  ['lib/stableGeoFromLabel.test.js', `import { describe, it, expect } from 'vitest'
import { stableGeoFromLabel } from './stableGeoFromLabel.js'
describe('stableGeoFromLabel', () => {
  it('deterministic', () => {
    expect(stableGeoFromLabel('foo')).toEqual(stableGeoFromLabel('foo'))
  })
  it('israel shortcut', () => {
    const [lat] = stableGeoFromLabel('israel')
    expect(lat).toBeCloseTo(32.0853, 1)
  })
})`],
  ['lib/realityKindMeta.test.js', `import { describe, it, expect } from 'vitest'
import { REALITY_KIND_META } from './realityKindMeta.js'
describe('realityKindMeta', () => {
  it('has live meta', () => expect(REALITY_KIND_META.live).toBeTruthy())
})`],
  ['lib/engineGroupDefs.test.js', `import { describe, it, expect } from 'vitest'
import { ENGINE_GROUP_DEFS, ENGINE_GROUPS } from './engineGroupDefs.js'
describe('engineGroupDefs', () => {
  it('groups defined', () => {
    expect(ENGINE_GROUP_DEFS.length).toBeGreaterThan(5)
    expect(ENGINE_GROUPS.recon.label).toBeTruthy()
  })
})`],
  ['lib/useJobPoll.test.js', `import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus, extractFindingsFromJob } from './useJobPoll.js'
describe('useJobPoll helpers', () => {
  it('normalizeJobStatus', () => expect(normalizeJobStatus('COMPLETED')).toBe('completed'))
  it('uiJobStatus', () => expect(typeof uiJobStatus('running')).toBe('string'))
  it('extractFindingsFromJob', () => {
    const f = extractFindingsFromJob({ result: { findings: [{ id: 1 }] } })
    expect(f.length).toBe(1)
  })
})`],
  ['lib/sseStream.test.js', `import { describe, it, expect } from 'vitest'
import { SSE_CONNECTING, SSE_OPEN, SSE_CLOSED } from './sseStream.js'
describe('sseStream constants', () => {
  it('states', () => {
    expect(SSE_CONNECTING).toBe(0)
    expect(SSE_OPEN).toBe(1)
    expect(SSE_CLOSED).toBe(2)
  })
})`],
  ['lib/engineClientPrefill.test.js', `import { describe, it, expect } from 'vitest'
import { buildScanPayload, normalizeIntegrations, mergeScanBody } from './engineClientPrefill.js'
describe('engineClientPrefill', () => {
  it('buildScanPayload', () => {
    const b = buildScanPayload('osint', { clientId: 1, target: 'https://x.test' })
    expect(b.engine).toBe('osint')
  })
  it('normalizeIntegrations empty', () => {
    expect(normalizeIntegrations(null)).toEqual({})
  })
  it('mergeScanBody', () => {
    const m = mergeScanBody('osint', { target: 'https://a.test' })
    expect(m.target).toBeTruthy()
  })
})`],
  ['lib/apiBase.test.js', `import { describe, it, expect } from 'vitest'
import { apiUrl, formatHttpApiError } from './apiBase.js'
describe('apiBase', () => {
  it('apiUrl path', () => expect(apiUrl('/api/health')).toMatch(/\\/api\\/health$/))
  it('formatHttpApiError', () => {
    expect(formatHttpApiError({ status: 503 }, 'busy')).toContain('503')
  })
})`],
  ['battlespace/commanderIntent.test.js', `import { describe, it, expect } from 'vitest'
import { buildAdjacency, findPerimeterNodes, nodesReachableToTarget } from './commanderIntent.js'
describe('commanderIntent', () => {
  it('adjacency', () => {
    const a = buildAdjacency([{ source: '1', target: '2' }])
    expect(a.get('1')?.has('2')).toBe(true)
  })
  it('perimeter', () => {
    expect(findPerimeterNodes([{ id: 'p', internet_exposed: true }])).toContain('p')
  })
  it('reachable nodes', () => {
    const adj = buildAdjacency([{ source: 'a', target: 'b' }, { source: 'b', target: 'c' }])
    const nodes = nodesReachableToTarget(['a'], 'c', adj)
    expect(nodes.has('c')).toBe(true)
  })
})`],
  ['lib/engineParamDefs.test.js', `import { describe, it, expect } from 'vitest'
import { getEngineParams, getCommandCenterRoute } from './engineParamDefs.js'
describe('engineParamDefs', () => {
  it('osint params', () => {
    const p = getEngineParams('osint')
    expect(Array.isArray(p)).toBe(true)
  })
  it('command center route', () => {
    expect(getCommandCenterRoute('osint')).toContain('/command-center')
  })
})`],
  ['lib/enginesRegistryLoader.test.js', `import { describe, it, expect } from 'vitest'
import { loadEnginesRegistry, getEnginesRegistrySync } from './enginesRegistryLoader.js'
describe('enginesRegistryLoader', () => {
  it('loads registry', () => {
    const r = loadEnginesRegistry()
    expect(r && typeof r === 'object').toBe(true)
  })
  it('sync getter', () => {
    loadEnginesRegistry()
    expect(getEnginesRegistrySync()).toBeTruthy()
  })
})`],
  ['lib/engineParamDefsLoader.test.js', `import { describe, it, expect } from 'vitest'
import { loadGeneratedParamDefs, getGeneratedParamDefsSync } from './engineParamDefsLoader.js'
describe('engineParamDefsLoader', () => {
  it('loads defs', () => {
    const d = loadGeneratedParamDefs()
    expect(d && typeof d === 'object').toBe(true)
  })
  it('sync getter', () => {
    loadGeneratedParamDefs()
    expect(getGeneratedParamDefsSync()).toBeTruthy()
  })
})`],
  ['lib/useProductionEngines.test.js', `import { describe, it, expect } from 'vitest'
import { invalidateProductionEnginesCache } from './useProductionEngines.js'
describe('useProductionEngines cache', () => {
  it('invalidate noop', () => expect(() => invalidateProductionEnginesCache()).not.toThrow())
})`],
  ['lib/useEngineCapabilities.test.js', `import { describe, it, expect } from 'vitest'
import { invalidateEngineCapabilitiesCache } from './useEngineCapabilities.js'
describe('useEngineCapabilities cache', () => {
  it('invalidate noop', () => expect(() => invalidateEngineCapabilitiesCache()).not.toThrow())
})`],
  ['lib/engineParamDefsExplicit.test.js', `import { describe, it, expect } from 'vitest'
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
describe('engineParamDefsExplicit', () => {
  it('has profiles', () => expect(Object.keys(EXPLICIT_PARAM_DEFS).length).toBeGreaterThan(10))
})`],
  ['lib/engineParamDefsGroups.test.js', `import { describe, it, expect } from 'vitest'
import { GROUP_PARAMS } from './engineParamDefsGroups.js'
describe('engineParamDefsGroups', () => {
  it('groups object', () => expect(typeof GROUP_PARAMS).toBe('object'))
})`],
  ['lib/strategicEngineProgram.test.js', `import { describe, it, expect } from 'vitest'
import { STRATEGIC_ENGINE_PROGRAM, strategicEnginesNeedingDedicatedPage } from './strategicEngineProgram.js'
describe('strategicEngineProgram', () => {
  it('phases', () => expect(STRATEGIC_ENGINE_PROGRAM.length).toBeGreaterThan(0))
  it('dedicated pages', () => expect(strategicEnginesNeedingDedicatedPage().length).toBeGreaterThan(0))
})`],
  ['lib/topTierEngineProfiles.test.js', `import { describe, it, expect } from 'vitest'
import { TOP_TIER_ENGINE_IDS, getTopTierProfile, isTopTierEngine } from './topTierEngineProfiles.js'
describe('topTierEngineProfiles', () => {
  it('ids non-empty', () => expect(TOP_TIER_ENGINE_IDS.length).toBeGreaterThan(0))
  it('profile lookup', () => {
    const id = TOP_TIER_ENGINE_IDS[0]
    expect(getTopTierProfile(id)).toBeTruthy()
    expect(isTopTierEngine(id)).toBe(true)
  })
})`],
  ['lib/engineIntegrationReadiness.test.js', `import { describe, it, expect } from 'vitest'
import { computeEngineIntegrationReadiness } from './engineIntegrationReadiness.js'
describe('engineIntegrationReadiness', () => {
  it('osint readiness', () => {
    const r = computeEngineIntegrationReadiness('osint', {})
    expect(r).toHaveProperty('ready')
  })
})`],
  ['lib/enginesRegistry.test.js', `import { describe, it, expect } from 'vitest'
import { ENGINES_REGISTRY, getEngine, getEnginesByGroup } from './enginesRegistry.js'
describe('enginesRegistry', () => {
  it('non-empty', () => expect(ENGINES_REGISTRY.length).toBeGreaterThan(100))
  it('getEngine', () => expect(getEngine('osint')?.id).toBe('osint'))
  it('by group', () => expect(getEnginesByGroup('recon').length).toBeGreaterThan(0))
})`],
  ['lib/launchEngineScan.test.js', `import { describe, it, expect, vi } from 'vitest'
vi.mock('./apiBase.js', () => ({
  apiFetch: vi.fn(async () => ({ ok: true, json: async () => ({ job_id: '1' }) })),
}))
import { launchEngineScan } from './launchEngineScan.js'
describe('launchEngineScan', () => {
  it('posts scan', async () => {
    const r = await launchEngineScan({ engineId: 'osint', clientId: 1, target: 'https://x.test' })
    expect(r.ok).toBe(true)
  })
})`],
  ['lib/engineHistorySummary.test.js', `import { describe, it, expect } from 'vitest'
import { invalidateEngineHistorySummary } from './engineHistorySummary.js'
describe('engineHistorySummary', () => {
  it('invalidate noop', () => expect(() => invalidateEngineHistorySummary()).not.toThrow())
})`],
  ['forensic/forensicShadowHost.test.js', `import { describe, it, expect } from 'vitest'
import { mountForensicShadow } from './forensicShadowHost.js'
describe('forensicShadowHost', () => {
  it('mounts closed shadow', () => {
    const host = document.createElement('div')
    document.body.appendChild(host)
    const shadow = mountForensicShadow(host, '<span class="forensic-badge">ok</span>')
    expect(shadow).toBeTruthy()
    host.remove()
  })
})`],
  ['hooks/useEngineRequirements.test.js', `import { describe, it, expect } from 'vitest'
import { computeLocalReadiness, buildClientPayload, defaultOnboardingForm, ALL_MODULE_IDS } from './useEngineRequirements.js'
describe('useEngineRequirements helpers', () => {
  it('default form', () => expect(defaultOnboardingForm().contact_email).toBe(''))
  it('modules', () => expect(ALL_MODULE_IDS.length).toBeGreaterThan(0))
  it('readiness empty catalog', () => {
    expect(computeLocalReadiness(null, null, {}, []).ready).toBe(false)
  })
  it('buildClientPayload', () => {
    const p = buildClientPayload({ ...defaultOnboardingForm(), name: 'Acme', scope_domains: 'a.com' })
    expect(p.name).toBe('Acme')
  })
})`],
  ['boot/intentPrefetch.test.js', `import { describe, it, expect } from 'vitest'
import { predictChainFromRoute } from './intentPrefetch.js'
describe('intentPrefetch', () => {
  it('predicts chain', () => {
    const chain = predictChainFromRoute('/command-center/operations')
    expect(Array.isArray(chain)).toBe(true)
  })
})`],
  ['lib/routeEngineId.extra.test.js', `import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId } from './routeEngineId.js'
describe('routeEngineId extra', () => {
  it('osint route', () => expect(resolveRouteEngineId('/engines/osint')).toBeTruthy())
})`],
  ['lib/routeEvidence.extra.test.js', `import { describe, it, expect } from 'vitest'
import { resolveRouteEvidence, ROUTE_EVIDENCE } from './routeEvidence.js'
describe('routeEvidence extra', () => {
  it('engines key', () => expect(ROUTE_EVIDENCE['/engines']).toBeTruthy())
  it('resolve', () => {
    const t = resolveRouteEvidence('/engines', (k) => k)
    expect(t).toBe('engines.evidence_notice')
  })
})`],
  ['lib/appNav.extra.test.js', `import { describe, it, expect } from 'vitest'
import { isNavActive, findNavMatch, canAccessNavItem } from './appNav.js'
describe('appNav extra', () => {
  it('isNavActive', () => expect(isNavActive('/command-center/operations', '/command-center/operations')).toBe(true))
  it('findNavMatch', () => expect(findNavMatch('/command-center/operations')).toBeTruthy())
  it('canAccessNavItem admin', () => {
    expect(canAccessNavItem({ to: '/admin' }, { is_superadmin: true })).toBe(true)
  })
})`],
  ['components/ui/EvidenceNotice.test.jsx', `import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EvidenceNotice from './EvidenceNotice.jsx'
describe('EvidenceNotice', () => {
  it('renders children', () => {
    render(<EvidenceNotice>Live API evidence</EvidenceNotice>)
    expect(screen.getByText(/Live API evidence/)).toBeInTheDocument()
  })
  it('null when empty', () => {
    const { container } = render(<EvidenceNotice />)
    expect(container.firstChild).toBeNull()
  })
})`],
  ['lib/apiBase.tokens.test.js', `import { describe, it, expect, beforeEach } from 'vitest'
import { getStoredAccessToken, setStoredAccessToken, clearStoredAccessToken } from './apiBase.js'
describe('apiBase tokens', () => {
  beforeEach(() => clearStoredAccessToken())
  it('round trip', () => {
    setStoredAccessToken('tok')
    expect(getStoredAccessToken()).toBe('tok')
    clearStoredAccessToken()
    expect(getStoredAccessToken()).toBeNull()
  })
})`],
  ['lib/enginesRegistry.targetless.test.js', `import { describe, it, expect } from 'vitest'
import { TARGETLESS_ENGINE_IDS } from './enginesRegistry.js'
describe('targetless engines', () => {
  it('set non-empty', () => expect(TARGETLESS_ENGINE_IDS.size).toBeGreaterThan(0))
})`],
  ['lib/engineParamDefs.routes.test.js', `import { describe, it, expect } from 'vitest'
import { ENGINE_COMMAND_CENTER_ROUTES, getEngineParamKeys } from './engineParamDefs.js'
describe('engineParamDefs routes', () => {
  it('routes map', () => expect(Object.keys(ENGINE_COMMAND_CENTER_ROUTES).length).toBeGreaterThan(50))
  it('param keys', () => expect(Array.isArray(getEngineParamKeys('osint'))).toBe(true))
})`],
  ['lib/exportFindingsCsv.policy.test.js', `import { describe, it, expect } from 'vitest'
import { exportPolicyFindingsCsv } from './exportFindingsCsv.js'
describe('exportPolicyFindingsCsv', () => {
  it('triggers download', () => {
    const clicked = []
    const orig = document.createElement
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') el.click = () => clicked.push(1)
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}
    exportPolicyFindingsCsv([{ control: 'AC-1', status: 'fail' }], 'policy')
    document.createElement = orig
    expect(clicked.length).toBe(1)
  })
})`],
  ['lib/sanitizeFinding.truncate.test.js', `import { describe, it, expect } from 'vitest'
import { sanitizeFindingPlainText } from './sanitizeFinding.js'
describe('sanitizeFinding truncate', () => {
  it('max len', () => expect(sanitizeFindingPlainText('abc', 2)).toContain('[truncated]'))
})`],
  ['lib/clientTarget.domains.test.js', `import { describe, it, expect } from 'vitest'
import { clientPrimaryTargetUrl } from './clientTarget.js'
describe('clientTarget domains', () => {
  it('array domains', () => {
    expect(clientPrimaryTargetUrl({ domains: ['x.test'] })).toBe('https://x.test')
  })
  it('empty', () => expect(clientPrimaryTargetUrl({})).toBe(''))
})`],
  ['lib/engineClientPrefill.defaults.test.js', `import { describe, it, expect } from 'vitest'
import { buildDefaultEngineParams, prefillParamsForEngine } from './engineClientPrefill.js'
describe('engineClientPrefill defaults', () => {
  it('default params', () => expect(buildDefaultEngineParams('osint')).toBeTruthy())
  it('prefill', () => {
    const p = prefillParamsForEngine('osint', {}, {})
    expect(typeof p).toBe('object')
  })
})`],
  ['lib/realityKindMeta.kinds.test.js', `import { describe, it, expect } from 'vitest'
import { REALITY_KIND_META } from './realityKindMeta.js'
describe('realityKindMeta kinds', () => {
  for (const k of ['live', 'hybrid', 'catalog']) {
    it(\`has \${k}\`, () => expect(REALITY_KIND_META[k]).toBeTruthy())
  }
})`],
  ['lib/useJobPoll.status.test.js', `import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus } from './useJobPoll.js'
describe('job status mapping', () => {
  it('failed', () => expect(normalizeJobStatus('FAILED')).toBe('failed'))
  it('ui pending', () => expect(uiJobStatus('queued')).toBeTruthy())
})`],
  ['lib/routeEngineId.resolve.test.js', `import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId, ROUTE_ENGINE_ID } from './routeEngineId.js'
describe('routeEngineId resolve', () => {
  it('proxy map', () => expect(ROUTE_ENGINE_ID['/engines/osint']).toBeTruthy())
  it('unknown path', () => expect(resolveRouteEngineId('/unknown')).toBeFalsy())
})`],
  ['lib/appNav.breadcrumbs.test.js', `import { describe, it, expect } from 'vitest'
import { buildBreadcrumbs, PRIMARY_NAV } from './appNav.js'
describe('appNav breadcrumbs', () => {
  it('primary nav', () => expect(PRIMARY_NAV.length).toBeGreaterThan(3))
  it('breadcrumbs', () => {
    const c = buildBreadcrumbs('/engines', { pageTitle: 'Engines', t: (k) => k })
    expect(c.length).toBeGreaterThan(0)
  })
})`],
  ['lib/topTierEngineProfiles.more.test.js', `import { describe, it, expect } from 'vitest'
import { isTopTierEngine } from './topTierEngineProfiles.js'
describe('topTierEngineProfiles more', () => {
  it('non top tier', () => expect(isTopTierEngine('osint')).toBe(false))
})`],
  ['lib/strategicEngineProgram.pages.test.js', `import { describe, it, expect } from 'vitest'
import { strategicEnginesNeedingDedicatedPage } from './strategicEngineProgram.js'
describe('strategic dedicated pages', () => {
  it('unique ids', () => {
    const ids = strategicEnginesNeedingDedicatedPage()
    expect(new Set(ids).size).toBe(ids.length)
  })
})`],
  ['lib/engineIntegrationReadiness.github.test.js', `import { describe, it, expect } from 'vitest'
import { computeEngineIntegrationReadiness } from './engineIntegrationReadiness.js'
describe('integration readiness github', () => {
  it('leak_hunter with github', () => {
    const r = computeEngineIntegrationReadiness('leak_hunter', { github: { connected: true } })
    expect(r.percent).toBeGreaterThanOrEqual(0)
  })
})`],
  ['lib/enginesRegistry.byId.test.js', `import { describe, it, expect } from 'vitest'
import { ENGINES_BY_ID } from './enginesRegistry.js'
describe('ENGINES_BY_ID', () => {
  it('indexed', () => expect(ENGINES_BY_ID.osint?.id).toBe('osint'))
})`],
  ['lib/engineGroupDefs.ids.test.js', `import { describe, it, expect } from 'vitest'
import { ENGINE_GROUP_DEFS } from './engineGroupDefs.js'
describe('ENGINE_GROUP_DEFS ids', () => {
  it('unique', () => {
    const ids = ENGINE_GROUP_DEFS.map((g) => g.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})`],
  ['lib/sseStream.open.test.js', `import { describe, it, expect } from 'vitest'
import { openSseStream } from './sseStream.js'
describe('openSseStream', () => {
  it('returns handle', () => {
    const h = openSseStream('/api/events')
    expect(h).toHaveProperty('close')
    h.close()
  })
})`],
  ['lib/pdfExport.lines.test.js', `import { describe, it, expect } from 'vitest'
import { buildSimpleTextPdf } from './pdfExport.js'
describe('pdfExport lines', () => {
  it('multi line', () => {
    const b = buildSimpleTextPdf(['a', 'b', 'c'])
    expect(b.byteLength).toBeGreaterThan(50)
  })
})`],
  ['lib/aliasClient.paths.test.js', `import { describe, it, expect } from 'vitest'
import { withClientId } from './aliasClient.js'
describe('aliasClient paths', () => {
  it('existing query', () => expect(withClientId('/a?x=1', 2)).toContain('client_id=2'))
})`],
  ['lib/apiError.detail.test.js', `import { describe, it, expect } from 'vitest'
import { formatApiErrorFromBody } from './apiError.js'
describe('apiError detail variants', () => {
  it('message field', () => expect(formatApiErrorFromBody({ message: 'm' }, 400)).toBe('m'))
  it('array detail', () => {
    expect(formatApiErrorFromBody({ detail: [{ msg: 'a' }] }, 422)).toContain('a')
  })
})`],
  ['lib/stableGeoFromLabel.hash.test.js', `import { describe, it, expect } from 'vitest'
import { stableGeoFromLabel } from './stableGeoFromLabel.js'
describe('stableGeoFromLabel hash', () => {
  it('different labels', () => {
    expect(stableGeoFromLabel('a')).not.toEqual(stableGeoFromLabel('b'))
  })
})`],
  ['lib/formatHttpApiError.test.js', `import { describe, it, expect } from 'vitest'
import { formatHttpApiError } from './apiBase.js'
describe('formatHttpApiError', () => {
  it('404 helpful', () => {
    expect(formatHttpApiError({ status: 404 }, '')).toMatch(/404/)
  })
  it('503 detail', () => {
    expect(formatHttpApiError({ status: 503, statusText: 'Unavailable' }, 'busy')).toContain('busy')
  })
})`],
]

let created = 0
for (const [rel, body] of specs) {
  const abs = path.join(fe, rel)
  if (fs.existsSync(abs)) continue
  fs.mkdirSync(path.dirname(abs), { recursive: true })
  fs.writeFileSync(abs, body)
  created += 1
}

function countTests(dir) {
  let n = 0
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name)
    if (ent.isDirectory()) n += countTests(p)
    else if (/\.(test|spec)\.(js|jsx)$/.test(ent.name)) n += 1
  }
  return n
}

const plugins = path.join(root, 'frontend/plugins')
const total = countTests(fe) + countTests(plugins)
console.log(`Created ${created} tests; total test files under src+plugins: ${total}`)
