/**
 * Route → live API evidence banner (i18n key).
 * PageShell auto-renders unless path is in ROUTE_EVIDENCE_SKIP or page passes hideEvidence.
 */

/** Paths that already render evidence inside page content — avoid duplicate banners. */
export const ROUTE_EVIDENCE_SKIP = new Set([
  '/',
  '/ask',
  '/audit-log',
  '/billing',
  '/findings',
  '/playbooks',
  '/vuln-intel',
  '/status',
  '/clients/new',
  '/council-queue',
  '/incident-response',
  '/threat-hunting',
  '/engine-management',
  '/template-engine',
  '/risk-graph',
  '/system-config',
  '/network-protocols',
  '/metrics',
  '/jobs',
  '/dark-web',
  '/verification/oob',
  '/compliance',
  '/baseline-drift',
  '/kill-chain',
  '/ai-analysis',
  '/domain-discovery',
  '/engines/top-tier',
  '/engines/osint',
  '/ceo',
])

/** Prefixes where child pages render their own evidence banner. */
export const ROUTE_EVIDENCE_SKIP_PREFIX = [
  '/engines/top-tier/',
  '/engines/business/',
]

/** Exact pathname → i18n key (basename-relative, no trailing slash). */
export const ROUTE_EVIDENCE = {
  '/clients': 'clients_page.evidence_notice',
  '/engines': 'engines.evidence_notice',
  '/jwt-lab': 'pages.jwtAttackLab.evidence_notice',
  '/iac-security': 'pages.iacSecurityCenter.evidence_notice',
  '/graphql-security': 'pages.graphqlSecurityCommandCenter.evidence_notice',
  '/attack-surface': 'pages.attackSurfaceManagement.evidence_notice',
  '/dns-posture': 'pages.dnsDomainPosture.evidence_notice',
  '/cache-posture': 'pages.webCachePosture.evidence_notice',
  '/http-smuggling': 'pages.httpSmugglingPosture.evidence_notice',
  '/email-posture': 'pages.emailDnsPosture.evidence_notice',
  '/transport-security': 'pages.transportSecurityCommandCenter.evidence_notice',
  '/tls-posture': 'pages.pkiTlsCommandCenter.evidence_notice',
  '/cloud-posture': 'pages.cloudPostureCommandCenter.evidence_notice',
  '/detection-surface': 'pages.edDetectionSurface.evidence_notice',
  '/waf-bypass': 'pages.wafBypassLab.evidence_notice',
  '/file-upload-lab': 'pages.fileUploadSecurityLab.evidence_notice',
  '/identity-security': 'pages.identitySecurityCenter.evidence_notice',
  '/kerberos-security': 'pages.kerberosSecurityCommandCenter.evidence_notice',
  '/smb-netbios': 'pages.smbNetbiosCommandCenter.evidence_notice',
  '/password-spray': 'pages.passwordSprayCommandCenter.evidence_notice',
  '/saml-security': 'pages.samlSecurityCommandCenter.evidence_notice',
  '/cicd-security': 'pages.cicdPipelineSecurityCommandCenter.evidence_notice',
  '/serverless-security': 'pages.serverlessSecurityCommandCenter.evidence_notice',
  '/threat-intel': 'pages.threatIntelHub.evidence_notice',
  '/threat-analysis': 'pages.threatAnalysisCenter.evidence_notice',
  '/engine-reliability': 'pages.engineReliability.evidence_notice',
  '/admin': 'pages.adminManagement.evidence_notice',
  '/cloud': 'pages.cloudControlTower.evidence_notice',
  '/network': 'pages.networkIntelligence.evidence_notice',
  '/supply-chain': 'pages.supplyChainHub.evidence_notice',
  '/pqc-radar': 'pages.pqcRadar.evidence_notice',
  '/nexus-swarm': 'pages.nexusSovereignSwarm.evidence_notice',
  '/digital-twin': 'pages.digitalTwinSimulator.evidence_notice',
  '/ast-fuzzing': 'pages.astFuzzingStudio.evidence_notice',
  '/feedback-loop': 'pages.feedbackLoopVerification.evidence_notice',
  '/engine-catalog': 'pages.engineClientCatalog.evidence_notice',
  '/rate-limits': 'pages.rateLimitAnalytics.evidence_notice',
  '/mobile-security': 'pages.mobileSecurity.evidence_notice',
  '/ot-ics': 'pages.otIcsSecurity.evidence_notice',
  '/social-engineering': 'pages.socialEngineering.evidence_notice',
  '/remediation': 'pages.remediationHub.evidence_notice',
  '/ceo-vault': 'pages.ceoVault.evidence_notice',
  '/sbom': 'pages.sbomBrowser.evidence_notice',
  '/integrations': 'pages.integrationManager.evidence_notice',
  '/alert-rules': 'pages.alertRulesEngine.evidence_notice',
  '/scan-scheduler': 'pages.scanScheduler.evidence_notice',
  '/containment-rules': 'pages.containmentRulesBuilder.evidence_notice',
  '/identity-context': 'pages.identityContextManager.evidence_notice',
  '/exploit-lab': 'pages.exploitResearchLab.evidence_notice',
  '/agents': 'pages.agentManagement.evidence_notice',
  '/roe-approvals': 'pages.roeApprovals.evidence_notice',
  '/sso-config': 'pages.ssoDashboard.evidence_notice',
  '/threat-emulation': 'pages.threatEmulation.evidence_notice',
  '/oast': 'pages.oastDashboard.evidence_notice',
  '/zero-day-radar': 'pages.zeroDayRadar.evidence_notice',
  '/operations': 'pages.cockpit.evidence_notice',
  '/system-core': 'pages.systemCore.evidence_notice',
  '/engines/strategic': 'pages.strategicEngineProgram.evidence_notice',
  '/intel-map': 'pages.intelMap.evidence_notice',
}

/** Longest-prefix-first dynamic routes → i18n key. */
export const ROUTE_EVIDENCE_PREFIX = [
  { prefix: '/clients/', key: 'pages.clientDetail.evidence_notice' },
  { prefix: '/engines/', key: 'pages.engineDetail.evidence_notice' },
  { prefix: '/digital-twin/', key: 'pages.digitalTwinSimulator.evidence_notice' },
]

function normalizePath(pathname) {
  const p = (pathname || '').replace(/\/$/, '') || '/'
  return p
}

function isSkipped(path) {
  if (ROUTE_EVIDENCE_SKIP.has(path)) return true
  return ROUTE_EVIDENCE_SKIP_PREFIX.some(
    (prefix) => path === prefix.replace(/\/$/, '') || path.startsWith(prefix),
  )
}

function resolveKey(path) {
  if (ROUTE_EVIDENCE[path]) return ROUTE_EVIDENCE[path]
  for (const { prefix, key } of ROUTE_EVIDENCE_PREFIX) {
    if (path === prefix.replace(/\/$/, '') || path.startsWith(prefix)) return key
  }
  return null
}

/**
 * @param {string} pathname
 * @param {(key: string, opts?: object) => string} t
 * @returns {string | null}
 */
export function resolveRouteEvidence(pathname, t) {
  const path = normalizePath(pathname)
  if (isSkipped(path)) return null
  const key = resolveKey(path)
  if (!key) return null
  const text = t(key, { defaultValue: '' })
  return text && text !== key ? text : null
}
