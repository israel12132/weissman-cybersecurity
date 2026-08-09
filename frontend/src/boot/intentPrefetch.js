/**
 * Predictive micro-chunk pre-fetch — eliminates click-lag on route transitions.
 */
import { matchRouteChunk, normalizeRoutePath } from '../routing/routePrefetchMap'

/** @type {Set<string>} */
const inflight = new Set()

/** Attack-chain heuristics: preload likely next operator surfaces. */
const CHAIN_PREDICT = {
  '/': ['/engines', '/findings', '/clients'],
  '/operations': ['/engines', '/findings'],
  '/engines': ['/jwt-lab', '/waf-bypass', '/graphql-security', '/template-engine'],
  '/kill-chain': ['/threat-emulation', '/exploit-lab', '/roe-approvals'],
  '/threat-emulation': ['/kill-chain', '/agents'],
  '/findings': ['/remediation', '/incident-response'],
  '/clients': ['/domain-discovery', '/jobs'],
  '/template-engine': ['/ast-fuzzing', '/file-upload-lab'],
  '/ast-fuzzing': ['/template-engine', '/feedback-loop'],
  '/intel-map': ['/threat-intel', '/risk-graph', '/dark-web'],
}

/**
 * Preload a route's lazy chunk (idempotent, deduped).
 * @param {string} path
 */
export function prefetchRoute(path) {
  const normalized = normalizeRoutePath(path)
  const loader = matchRouteChunk(normalized)
  if (!loader || inflight.has(normalized)) return
  inflight.add(normalized)
  // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
  const p = loader().catch(() => {}).finally(() => inflight.delete(normalized))
  void p
}

/** Hover / focus intent — preload target route chunk. */
export function onNavIntent(path) {
  prefetchRoute(path)
  const normalized = normalizeRoutePath(path)
  const related = CHAIN_PREDICT[normalized] || []
  for (const next of related.slice(0, 2)) prefetchRoute(next)
}

/** After navigation, warm predicted follow-on routes during idle. */
export function predictChainFromRoute(pathname) {
  const normalized = normalizeRoutePath(pathname)
  const chain = CHAIN_PREDICT[normalized]
  if (!chain?.length) return

  const run = () => {
    for (const p of chain) prefetchRoute(p)
  }

  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(run, { timeout: 2500 })
  } else {
    setTimeout(run, 120)
  }
}

