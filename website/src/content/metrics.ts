/**
 * Canonical marketing metrics. Every numeric claim must be verifiable from repo
 * tooling. Do not invent customers, certifications, or unpublished statistics.
 *
 * Verify:
 *   node scripts/verify_engine_wiring.mjs
 *   node scripts/engine_reality_audit.mjs
 *   node scripts/weissman-ui-audit.mjs
 *   node scripts/mitre_attack_coverage.mjs
 */
export const metrics = {
  /** Production engine IDs in the catalog (aliases + live probes + agent-required). */
  productionEngines: {
    value: 573,
    label: 'Production engines',
    verify: 'node scripts/verify_engine_wiring.mjs',
  },
  liveProbes: {
    value: 313,
    label: 'Live probes',
    verify: 'node scripts/engine_reality_audit.mjs',
  },
  engineAliases: {
    value: 212,
    label: 'Catalog aliases',
    verify: 'node scripts/engine_reality_audit.mjs',
  },
  agentRequired: {
    value: 48,
    label: 'Agent-required engines',
    verify: 'node scripts/engine_reality_audit.mjs',
  },
  commandCenterRoutes: {
    value: 146,
    label: 'Command Center routes',
    verify: 'node scripts/weissman-ui-audit.mjs',
  },
  auditedPages: {
    value: 127,
    label: 'Audited UI pages',
    verify: 'node scripts/weissman-ui-audit.mjs',
  },
  mitreTechniques: {
    value: 226,
    label: 'MITRE ATT&CK techniques',
    note: '194 primary + 32 code-grounded secondary, ATT&CK v19.1',
    verify: 'node scripts/mitre_attack_coverage.mjs',
  },
  agentDetections: {
    value: 15,
    label: 'On-host detections',
    verify: 'README.md — Endpoint agent',
  },
  kevRefreshHours: {
    value: 6,
    label: 'CISA KEV refresh (hours)',
    verify: 'README.md — Threat intel',
  },
  epssRefreshHours: {
    value: 12,
    label: 'FIRST EPSS refresh (hours)',
    verify: 'README.md — Threat intel',
  },
  slaUptime: {
    value: '99.95%',
    label: 'Cloud availability objective',
    verify: 'SLA_AND_STATUS.md',
  },
} as const
