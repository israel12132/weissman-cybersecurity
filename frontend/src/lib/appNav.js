/**
 * Single source of truth for AppShell navigation and breadcrumbs.
 * Only routes registered in main.jsx — no fake nav items.
 */

/** @typedef {{ to: string, labelKey: string, icon?: string, exact?: boolean }} NavItem */
/** @typedef {{ id: string, labelKey: string, items: NavItem[] }} NavGroup */

/** @type {NavGroup[]} */
export const NAV_GROUPS = [
  {
    id: 'command',
    labelKey: 'nav.groups.command',
    items: [
      { to: '/', labelKey: 'nav.cockpit', icon: '◈', exact: true },
      { to: '/engines', labelKey: 'nav.engine_matrix', icon: '⬡' },
      { to: '/clients', labelKey: 'nav.clients', icon: '🏢' },
      { to: '/jobs', labelKey: 'nav.jobs', icon: '⏱' },
      { to: '/ask', labelKey: 'nav.ask_weissman', icon: '💬' },
      { to: '/playbooks', labelKey: 'nav.playbooks', icon: '⚡' },
    ],
  },
  {
    id: 'intelligence',
    labelKey: 'nav.groups.intelligence',
    items: [
      { to: '/findings', labelKey: 'nav.findings', icon: '◉' },
      { to: '/vuln-intel', labelKey: 'nav.vuln_intel', icon: '🔬' },
      { to: '/threat-intel', labelKey: 'nav.threat_intel', icon: '🎯' },
      { to: '/threat-hunting', labelKey: 'nav.threat_hunting', icon: '🔭' },
      { to: '/dark-web', labelKey: 'nav.dark_web', icon: '🕸' },
      { to: '/intel-map', labelKey: 'nav.intel_map', icon: '🌐' },
      { to: '/incident-response', labelKey: 'nav.incident_response', icon: '🚨' },
    ],
  },
  {
    id: 'operations',
    labelKey: 'nav.groups.operations',
    items: [
      { to: '/threat-emulation', labelKey: 'nav.threat_emulation', icon: '◈' },
      { to: '/kill-chain', labelKey: 'nav.kill_chain', icon: '⛓' },
      { to: '/ai-analysis', labelKey: 'nav.ai_analysis', icon: '🧠' },
      { to: '/exploit-lab', labelKey: 'nav.exploit_lab', icon: '🧪' },
      { to: '/council-queue', labelKey: 'nav.council_queue', icon: '⚖' },
      { to: '/roe-approvals', labelKey: 'nav.roe_approvals', icon: '📜' },
      { to: '/remediation', labelKey: 'nav.remediation', icon: '🔧' },
      { to: '/agents', labelKey: 'nav.agents', icon: '📡' },
    ],
  },
  {
    id: 'engines',
    labelKey: 'nav.groups.engines',
    items: [
      { to: '/cloud', labelKey: 'nav.cloud', icon: '☁' },
      { to: '/supply-chain', labelKey: 'nav.supply_chain', icon: '⛓' },
      { to: '/network', labelKey: 'nav.network', icon: '⛢' },
      { to: '/pqc-radar', labelKey: 'nav.pqc_radar', icon: '🔐' },
      { to: '/oast', labelKey: 'nav.oast', icon: '⊂' },
      { to: '/verification/oob', labelKey: 'nav.oob_verify', icon: '◎' },
      { to: '/digital-twin', labelKey: 'nav.digital_twin', icon: '⟐' },
      { to: '/domain-discovery', labelKey: 'nav.domain_discovery', icon: '🔍' },
      { to: '/zero-day-radar', labelKey: 'nav.zero_day', icon: '☢' },
      { to: '/template-engine', labelKey: 'nav.template_engine', icon: '⟡' },
      { to: '/ast-fuzzing', labelKey: 'nav.ast_fuzzing', icon: '⧉' },
      { to: '/feedback-loop', labelKey: 'nav.feedback_loop', icon: '⟲' },
      { to: '/engine-catalog', labelKey: 'nav.engine_catalog', icon: '📋' },
    ],
  },
  {
    id: 'governance',
    labelKey: 'nav.groups.governance',
    items: [
      { to: '/compliance', labelKey: 'nav.compliance', icon: '🛡' },
      { to: '/sbom', labelKey: 'nav.sbom', icon: '📦' },
      { to: '/risk-graph', labelKey: 'nav.risk_graph', icon: '🕸' },
      { to: '/baseline-drift', labelKey: 'nav.baseline_drift', icon: '📊' },
      { to: '/rate-limits', labelKey: 'nav.rate_limits', icon: '⏱' },
      { to: '/mobile-security', labelKey: 'nav.mobile_security', icon: '📱' },
      { to: '/ot-ics', labelKey: 'nav.ot_ics', icon: '🏭' },
      { to: '/network-protocols', labelKey: 'nav.network_protocols', icon: '🔌' },
      { to: '/social-engineering', labelKey: 'nav.social_engineering', icon: '👥' },
      { to: '/alert-rules', labelKey: 'nav.alert_rules', icon: '🔔' },
      { to: '/containment-rules', labelKey: 'nav.containment_rules', icon: '🚧' },
      { to: '/scan-scheduler', labelKey: 'nav.scan_scheduler', icon: '📅' },
    ],
  },
  {
    id: 'administration',
    labelKey: 'nav.groups.administration',
    items: [
      { to: '/integrations', labelKey: 'nav.integrations', icon: '🔗' },
      { to: '/identity-context', labelKey: 'nav.identity_context', icon: '👤' },
      { to: '/sso-config', labelKey: 'nav.sso_config', icon: '🔑' },
      { to: '/engine-management', labelKey: 'nav.engine_management', icon: '⚙' },
      { to: '/system-config', labelKey: 'nav.system_config', icon: '⚙' },
      { to: '/metrics', labelKey: 'nav.metrics', icon: '📈' },
      { to: '/admin', labelKey: 'nav.admin', icon: '👑' },
      { to: '/ceo-vault', labelKey: 'nav.ceo_vault', icon: '🔒' },
      { to: '/audit-log', labelKey: 'nav.audit_log', icon: '📋' },
    ],
  },
]

/** Path-prefix overrides for dynamic routes not listed in the sidebar. */
const PATH_OVERRIDES = [
  { prefix: '/clients/new', groupId: 'command', labelKey: 'nav.client_new' },
  { prefix: '/clients/', groupId: 'command', labelKey: 'nav.client_detail' },
  { prefix: '/engines/top-tier/', groupId: 'engines', labelKey: 'nav.engine_profile' },
  { prefix: '/engines/top-tier', groupId: 'engines', labelKey: 'nav.top_tier_engines' },
  { prefix: '/engines/strategic', groupId: 'engines', labelKey: 'nav.strategic_engines' },
  { prefix: '/engines/business/', groupId: 'engines', labelKey: 'nav.business_engine' },
  { prefix: '/engines/', groupId: 'command', labelKey: 'nav.engine_detail' },
  { prefix: '/digital-twin/', groupId: 'engines', labelKey: 'nav.digital_twin' },
  { prefix: '/operations', groupId: 'command', labelKey: 'nav.operations_view' },
  { prefix: '/system-core', groupId: 'administration', labelKey: 'nav.system_core' },
]

/**
 * @param {string} pathname
 * @param {string} to
 * @param {boolean} [exact]
 */
export function isNavActive(pathname, to, exact = false) {
  const p = pathname.replace(/\/$/, '') || '/'
  const t = to.replace(/\/$/, '') || '/'
  if (t === '/' || exact) return p === t
  return p === t || p.startsWith(`${t}/`)
}

/** @returns {{ group: NavGroup, item: NavItem } | null} */
export function findNavMatch(pathname) {
  const p = pathname.replace(/\/$/, '') || '/'
  for (const group of NAV_GROUPS) {
    for (const item of group.items) {
      if (isNavActive(p, item.to, item.exact)) {
        return { group, item }
      }
    }
  }
  for (const ov of PATH_OVERRIDES) {
    const prefix = ov.prefix.replace(/\/$/, '')
    if (p === prefix || p.startsWith(`${prefix}/`)) {
      const group = NAV_GROUPS.find((g) => g.id === ov.groupId)
      if (group) {
        return {
          group,
          item: { to: p, labelKey: ov.labelKey, exact: true },
        }
      }
    }
  }
  return null
}

/**
 * Build breadcrumb trail: Dashboard → Section → Page
 * @param {string} pathname
 * @param {{ pageTitle?: string, t: (key: string) => string }} opts
 * @returns {{ to?: string, label: string }[]}
 */
export function buildBreadcrumbs(pathname, { pageTitle, t }) {
  const crumbs = [{ to: '/', label: t('nav.dashboard') }]
  const match = findNavMatch(pathname)

  if (!match) {
    if (pageTitle) crumbs.push({ label: pageTitle })
    return crumbs
  }

  crumbs.push({ label: t(match.group.labelKey) })
  const navLabel = t(match.item.labelKey)
  const finalLabel = pageTitle || navLabel

  if (
    match.item.to !== '/' &&
    !isNavActive(pathname, match.item.to, match.item.exact)
  ) {
    crumbs.push({ to: match.item.to, label: navLabel })
    crumbs.push({ label: finalLabel })
  } else if (pageTitle && pageTitle !== navLabel) {
    crumbs.push({ to: match.item.to, label: navLabel })
    crumbs.push({ label: pageTitle })
  } else {
    crumbs.push({ label: finalLabel })
  }

  return dedupeCrumbs(crumbs)
}

/** @param {{ to?: string, label: string }[]} crumbs */
function dedupeCrumbs(crumbs) {
  const out = []
  for (const c of crumbs) {
    const prev = out[out.length - 1]
    if (prev && prev.label === c.label && !c.to) continue
    out.push(c)
  }
  return out
}
