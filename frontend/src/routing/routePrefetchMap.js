/**
 * Route prefetch loaders ONLY — no React.lazy exports.
 * Kept separate from routeChunks.js to break circular imports:
 *   app-context → EngineManifestContext → intentPrefetch → routeChunks → pages → … → app-context
 */

export function normalizeRoutePath(pathname) {
  if (!pathname) return '/'
  let p = pathname
  if (p.startsWith('/command-center')) p = p.slice('/command-center'.length) || '/'
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  return p || '/'
}

/** Exact route loaders for tactical prefetch. */
const EXACT = {
  '/engines': () => import(/* webpackChunkName: "page-engines" */ '../pages/EngineMatrix'),
  '/template-engine': () => import(/* webpackChunkName: "page-template-engine" */ '../pages/TemplateEngineWorkbench'),
  '/ast-fuzzing': () => import(/* webpackChunkName: "page-ast-fuzzing" */ '../pages/AstFuzzingStudio'),
  '/intel-map': () => import(/* webpackChunkName: "page-intel-map" */ '../App'),
  '/findings': () => import(/* webpackChunkName: "page-findings" */ '../pages/FindingsCommandCenter'),
  '/kill-chain': () => import(/* webpackChunkName: "page-kill-chain" */ '../pages/KillChainOrchestrator'),
  '/kill-chain-commander': () => import(/* webpackChunkName: "page-kill-chain-commander" */ '../pages/KillChainCommander'),
  '/jwt-lab': () => import(/* webpackChunkName: "page-jwt-lab" */ '../pages/JwtAttackLab'),
  '/waf-bypass': () => import(/* webpackChunkName: "page-waf-bypass" */ '../pages/WafBypassLab'),
  '/graphql-security': () => import(/* webpackChunkName: "page-graphql" */ '../pages/GraphqlSecurityCommandCenter'),
  '/clients': () => import(/* webpackChunkName: "page-clients" */ '../pages/Clients'),
  '/threat-emulation': () => import(/* webpackChunkName: "page-threat-emulation" */ '../pages/ThreatEmulation'),
  '/exploit-lab': () => import(/* webpackChunkName: "page-exploit-lab" */ '../pages/ExploitResearchLab'),
  '/threat-intel': () => import(/* webpackChunkName: "page-threat-intel" */ '../pages/ThreatIntelHub'),
  '/dark-web': () => import(/* webpackChunkName: "page-dark-web" */ '../pages/DarkWebMonitor'),
  '/jobs': () => import(/* webpackChunkName: "page-jobs" */ '../pages/JobsDashboard'),
  '/pdf-intelligence': () => import(/* webpackChunkName: "page-pdf-intelligence" */ '../pages/PdfCommandCenter'),
  '/remediation': () => import(/* webpackChunkName: "page-remediation" */ '../pages/RemediationHub'),
  '/remediation-analytics': () => import(/* webpackChunkName: "page-remediation-analytics" */ '../pages/RemediationAnalytics'),
  '/incident-response': () => import(/* webpackChunkName: "page-incident" */ '../pages/IncidentResponseCenter'),
  '/agents': () => import(/* webpackChunkName: "page-agents" */ '../pages/AgentManagement'),
  '/domain-discovery': () => import(/* webpackChunkName: "page-domain-discovery" */ '../pages/DomainDiscovery'),
  '/feedback-loop': () => import(/* webpackChunkName: "page-feedback-loop" */ '../pages/FeedbackLoopVerification'),
  '/roe-approvals': () => import(/* webpackChunkName: "page-roe" */ '../pages/RoeApprovals'),
  '/operations': () => import(/* webpackChunkName: "cockpit-shell" */ '../Cockpit'),
  '/': () => import(/* webpackChunkName: "cockpit-shell" */ '../Cockpit'),
}

const PREFIX = [
  { prefix: '/engines/', loader: () => import('../pages/EngineDetail') },
  { prefix: '/clients/', loader: () => import('../pages/ClientDetail') },
]

export function matchRouteChunk(pathname) {
  const p = normalizeRoutePath(pathname)
  if (EXACT[p]) return EXACT[p]
  for (const { prefix, loader } of PREFIX) {
    if (p.startsWith(prefix)) return loader
  }
  return null
}
