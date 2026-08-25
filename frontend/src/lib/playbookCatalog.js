/**
 * SOAR playbook catalog — built-in operator-grade templates plus tenant-owned
 * custom templates persisted in localStorage.
 *
 * Built-ins are drafts only: selecting one never writes the API and never
 * enables isolate/page/webhook side-effects. The operator reviews params
 * (especially webhook URLs) and saves via POST /api/playbooks.
 *
 * Trigger / action shapes match the live DSL in fingerprint_engine/src/soar_playbook.rs.
 */

export const CUSTOM_STORAGE_KEY = 'weissman_playbook_custom_templates'

export const ACTION_KINDS = [
  { kind: 'set_status',   labelKey: 'playbooks.action.set_status',   params: { status: 'IN_PROGRESS' } },
  { kind: 'slack_notify', labelKey: 'playbooks.action.slack_notify', params: { url: '', template: '{{severity}}: {{title}} on {{target}}' } },
  { kind: 'webhook',      labelKey: 'playbooks.action.webhook',      params: { url: '', template: '{{title}}' } },
  { kind: 'open_pr',      labelKey: 'playbooks.action.open_pr',      params: { title: 'Auto-fix: {{title}}' } },
  { kind: 'isolate_host', labelKey: 'playbooks.action.isolate_host', params: { target: '{{target}}', duration_seconds: 900 } },
  { kind: 'page_oncall',  labelKey: 'playbooks.action.page_oncall',  params: { team: 'sec-oncall', severity: '{{severity}}' } },
  { kind: 'http_post',    labelKey: 'playbooks.action.http_post',    params: { url: '', body: {} } },
]

/** Curated engine IDs for the trigger chip bar — all exist in enginesRegistry. */
export const ENGINE_FILTER_OPTIONS = [
  'asm',
  'leak_hunter',
  'secrets_manager_attack',
  'credential_stuffing',
  'password_spray',
  'password_spray_advanced',
  'identity_attack_chain',
  'kerberos_attack_suite',
  'saml_attack',
  'cloud_iam_escalation',
  'iac_misconfig',
  'supply_chain',
  'ransomware_emulation',
  'ransomware_sim',
  'apt28_techniques',
  'apt29_techniques',
  'apt41_techniques',
  'apt_lateral_movement',
  'email_dns_posture',
  'subdomain_takeover',
  'tls_downgrade',
]

export const PLAYBOOK_CATEGORIES = [
  'containment',
  'identity',
  'exposure',
  'secrets',
  'cloud',
  'supply_chain',
  'threat',
  'custom',
]

const SLACK_WAR = '{{severity}} {{title}} on {{target}} · cvss={{cvss}} epss={{epss}} kev={{kev}} cve={{cve}} engine={{source}}'
const SLACK_TICKET = '[Weissman] {{severity}} {{title}} — {{target}} ({{source}})'

function act(kind, params) {
  return { kind, params }
}

/**
 * Built-in catalog. `enabled` is always false so a selected template cannot
 * fire isolate_host / page_oncall until an operator explicitly enables + saves.
 */
export const BUILTIN_PLAYBOOKS = [
  {
    id: 'kev-exposed-containment',
    category: 'containment',
    intensity: 'critical',
    mitre: ['T1190', 'T1486'],
    nameKey: 'playbooks.catalog.kev_exposed.name',
    descriptionKey: 'playbooks.catalog.kev_exposed.description',
    fallbackName: 'Critical KEV → isolate + page',
    fallbackDescription:
      'CISA-KEV critical finding on an internet-exposed asset: isolate 30m, page sec-oncall, mark IN_PROGRESS, war-room Slack.',
    trigger: {
      severity: ['critical'],
      kev: true,
      exposed: true,
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('isolate_host', { target: '{{target}}', duration_seconds: 1800 }),
      act('page_oncall', { team: 'sec-oncall', severity: 'critical' }),
      act('slack_notify', { url: '', template: `KEV CONTAINMENT · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'ransomware-kev-lockdown',
    category: 'containment',
    intensity: 'critical',
    mitre: ['T1486', 'T1490'],
    nameKey: 'playbooks.catalog.ransomware_kev.name',
    descriptionKey: 'playbooks.catalog.ransomware_kev.description',
    fallbackName: 'Ransomware KEV lockdown',
    fallbackDescription:
      'Critical/high KEV (ransomware-class) on exposed assets: isolate 60m, page on-call, freeze the ticket, notify Slack.',
    trigger: {
      severity: ['critical', 'high'],
      kev: true,
      exposed: true,
      cooldown_seconds: 1800,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('isolate_host', { target: '{{target}}', duration_seconds: 3600 }),
      act('page_oncall', { team: 'sec-oncall', severity: 'critical' }),
      act('slack_notify', { url: '', template: `RANSOMWARE KEV LOCKDOWN · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'epss-exposed-triage',
    category: 'exposure',
    intensity: 'high',
    mitre: ['T1190', 'T1588.006'],
    nameKey: 'playbooks.catalog.epss_exposed.name',
    descriptionKey: 'playbooks.catalog.epss_exposed.description',
    fallbackName: 'High-EPSS exposed triage',
    fallbackDescription:
      'Critical/high finding with EPSS ≥ 0.70 on an internet-exposed asset: open the ticket and fan out Slack + webhook (SIEM/ITSM).',
    trigger: {
      severity: ['critical', 'high'],
      exposed: true,
      epss_min: 0.7,
      cooldown_seconds: 7200,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('slack_notify', { url: '', template: `EPSS EXPOSED · ${SLACK_TICKET}` }),
      act('webhook', { url: '', template: SLACK_TICKET }),
    ],
  },
  {
    id: 'asm-critical-exposure',
    category: 'exposure',
    intensity: 'critical',
    mitre: ['T1595', 'T1190'],
    nameKey: 'playbooks.catalog.asm_critical.name',
    descriptionKey: 'playbooks.catalog.asm_critical.description',
    fallbackName: 'ASM critical exposure',
    fallbackDescription:
      'Attack-surface engine (asm) critical + internet-exposed: acknowledge, Slack war-room, webhook into the ticketing bus.',
    trigger: {
      severity: ['critical'],
      exposed: true,
      engines: ['asm'],
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('slack_notify', { url: '', template: `ASM CRITICAL · ${SLACK_WAR}` }),
      act('webhook', { url: '', template: SLACK_TICKET }),
    ],
  },
  {
    id: 'secret-leak-break-glass',
    category: 'secrets',
    intensity: 'critical',
    mitre: ['T1552', 'T1530'],
    nameKey: 'playbooks.catalog.secret_leak.name',
    descriptionKey: 'playbooks.catalog.secret_leak.description',
    fallbackName: 'Secret leak break-glass',
    fallbackDescription:
      'Leak hunter / secrets-manager / credential-stuffing critical or high: page on-call, freeze the finding, Slack the identity desk.',
    trigger: {
      severity: ['critical', 'high'],
      engines: ['leak_hunter', 'secrets_manager_attack', 'credential_stuffing'],
      cooldown_seconds: 1800,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('page_oncall', { team: 'identity-oncall', severity: 'critical' }),
      act('slack_notify', { url: '', template: `SECRET LEAK · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'identity-attack-containment',
    category: 'identity',
    intensity: 'critical',
    mitre: ['T1110', 'T1558', 'T1078'],
    nameKey: 'playbooks.catalog.identity_attack.name',
    descriptionKey: 'playbooks.catalog.identity_attack.description',
    fallbackName: 'Identity attack containment',
    fallbackDescription:
      'Password spray, Kerberos, SAML, or identity-attack-chain: isolate the host 15m, page identity on-call, mark IN_PROGRESS.',
    trigger: {
      severity: ['critical', 'high'],
      engines: [
        'identity_attack_chain',
        'password_spray',
        'password_spray_advanced',
        'kerberos_attack_suite',
        'saml_attack',
      ],
      cooldown_seconds: 1800,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('isolate_host', { target: '{{target}}', duration_seconds: 900 }),
      act('page_oncall', { team: 'identity-oncall', severity: '{{severity}}' }),
      act('slack_notify', { url: '', template: `IDENTITY ATTACK · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'cloud-iam-escalation',
    category: 'cloud',
    intensity: 'critical',
    mitre: ['T1078.004', 'T1548'],
    nameKey: 'playbooks.catalog.cloud_iam.name',
    descriptionKey: 'playbooks.catalog.cloud_iam.description',
    fallbackName: 'Cloud IAM escalation',
    fallbackDescription:
      'cloud_iam_escalation critical/high: page cloud on-call, freeze the finding, Slack the cloud desk. No isolate — cloud identity is not a host.',
    trigger: {
      severity: ['critical', 'high'],
      engines: ['cloud_iam_escalation'],
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('page_oncall', { team: 'cloud-oncall', severity: 'critical' }),
      act('slack_notify', { url: '', template: `CLOUD IAM · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'iac-supply-chain-pr',
    category: 'supply_chain',
    intensity: 'high',
    mitre: ['T1195', 'T1609'],
    nameKey: 'playbooks.catalog.iac_pr.name',
    descriptionKey: 'playbooks.catalog.iac_pr.description',
    fallbackName: 'IaC / supply-chain auto-PR',
    fallbackDescription:
      'iac_misconfig or supply_chain findings: open a remediation PR, mark IN_PROGRESS, notify Slack. Cooldown 24h to avoid PR storms.',
    trigger: {
      severity: ['critical', 'high', 'medium'],
      engines: ['iac_misconfig', 'supply_chain'],
      cooldown_seconds: 86400,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('open_pr', { title: 'Auto-fix: {{title}} on {{target}}', repo: '' }),
      act('slack_notify', { url: '', template: `IAC AUTO-PR · ${SLACK_TICKET}` }),
    ],
  },
  {
    id: 'apt-hunt-alert',
    category: 'threat',
    intensity: 'critical',
    mitre: ['T1583', 'T1071', 'T1021'],
    nameKey: 'playbooks.catalog.apt_hunt.name',
    descriptionKey: 'playbooks.catalog.apt_hunt.description',
    fallbackName: 'APT hunt alert',
    fallbackDescription:
      'APT28/29/41 or lateral-movement engines at critical/high: page threat-hunt, Slack the IR channel. No isolate — hunt first.',
    trigger: {
      severity: ['critical', 'high'],
      engines: ['apt28_techniques', 'apt29_techniques', 'apt41_techniques', 'apt_lateral_movement'],
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('page_oncall', { team: 'threat-hunt', severity: 'critical' }),
      act('slack_notify', { url: '', template: `APT HUNT · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'cve-current-wave',
    category: 'exposure',
    intensity: 'high',
    mitre: ['T1190', 'T1588.006'],
    nameKey: 'playbooks.catalog.cve_wave.name',
    descriptionKey: 'playbooks.catalog.cve_wave.description',
    fallbackName: 'CVE-2024/2025 wave',
    fallbackDescription:
      'Internet-exposed critical/high findings whose CVE starts with CVE-2024 or CVE-2025: page on-call, freeze, Slack.',
    trigger: {
      severity: ['critical', 'high'],
      exposed: true,
      cve_prefixes: ['CVE-2024', 'CVE-2025'],
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('page_oncall', { team: 'sec-oncall', severity: '{{severity}}' }),
      act('slack_notify', { url: '', template: `CVE WAVE · ${SLACK_WAR}` }),
    ],
  },
  {
    id: 'email-dns-takeover',
    category: 'exposure',
    intensity: 'high',
    mitre: ['T1584.001', 'T1530'],
    nameKey: 'playbooks.catalog.email_dns.name',
    descriptionKey: 'playbooks.catalog.email_dns.description',
    fallbackName: 'Email DNS / subdomain takeover',
    fallbackDescription:
      'email_dns_posture or subdomain_takeover at critical/high: open the ticket, Slack, webhook to DNS ops.',
    trigger: {
      severity: ['critical', 'high'],
      engines: ['email_dns_posture', 'subdomain_takeover'],
      cooldown_seconds: 3600,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('slack_notify', { url: '', template: `DNS / TAKEOVER · ${SLACK_WAR}` }),
      act('webhook', { url: '', template: SLACK_TICKET }),
    ],
  },
  {
    id: 'tls-downgrade-exposed',
    category: 'exposure',
    intensity: 'high',
    mitre: ['T1040', 'T1557'],
    nameKey: 'playbooks.catalog.tls_downgrade.name',
    descriptionKey: 'playbooks.catalog.tls_downgrade.description',
    fallbackName: 'TLS downgrade on exposed asset',
    fallbackDescription:
      'tls_downgrade critical/high on an internet-exposed asset: freeze the finding and Slack PKI/platform — no isolate.',
    trigger: {
      severity: ['critical', 'high'],
      exposed: true,
      engines: ['tls_downgrade'],
      cooldown_seconds: 7200,
    },
    actions: [
      act('set_status', { status: 'IN_PROGRESS' }),
      act('slack_notify', { url: '', template: `TLS DOWNGRADE · ${SLACK_TICKET}` }),
    ],
  },
]

export function blankPlaybook() {
  return {
    name: '',
    description: '',
    enabled: false,
    trigger: { severity: [], cooldown_seconds: 3600 },
    actions: [],
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function translate(t, key, fallback) {
  if (typeof t !== 'function') return fallback
  const out = t(key, fallback)
  if (out == null || out === key) return fallback
  return out
}

/** Instantiate a catalog entry (builtin or custom) as an unsaved editor draft. */
export function templateToDraft(template, t) {
  if (!template) return blankPlaybook()
  const name = template.nameKey
    ? translate(t, template.nameKey, template.fallbackName || template.name || '')
    : (template.name || '')
  const description = template.descriptionKey
    ? translate(t, template.descriptionKey, template.fallbackDescription || template.description || '')
    : (template.description || '')
  return {
    name,
    description,
    enabled: false,
    trigger: clone(template.trigger || { severity: [], cooldown_seconds: 3600 }),
    actions: clone(Array.isArray(template.actions) ? template.actions : []),
  }
}

export function isPlaybookAction(value) {
  return Boolean(value && typeof value === 'object' && typeof value.kind === 'string' && value.kind.trim())
}

export function isValidPlaybookDraft(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  if (value.trigger != null && (typeof value.trigger !== 'object' || Array.isArray(value.trigger))) return false
  if (value.actions != null && !Array.isArray(value.actions)) return false
  if (Array.isArray(value.actions) && !value.actions.every(isPlaybookAction)) return false
  return true
}

/**
 * Accept a saved playbook JSON, a catalog entry, or a `{trigger, actions}` blob.
 * Returns a draft or null if the payload cannot be used.
 */
export function parseImportedPlaybook(raw) {
  let value = raw
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (!isValidPlaybookDraft(value)) return null
  return {
    name: typeof value.name === 'string' ? value.name : '',
    description: typeof value.description === 'string' ? value.description : '',
    enabled: false,
    trigger: clone(value.trigger || { severity: [], cooldown_seconds: 3600 }),
    actions: clone(Array.isArray(value.actions) ? value.actions : []),
  }
}

export function loadCustomTemplates(storage = typeof localStorage === 'undefined' ? null : localStorage) {
  if (!storage) return []
  try {
    const raw = storage.getItem(CUSTOM_STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((item) => item && typeof item.id === 'string' && isValidPlaybookDraft(item))
      .map((item) => ({
        id: item.id,
        builtin: false,
        category: 'custom',
        intensity: item.intensity || 'medium',
        mitre: Array.isArray(item.mitre) ? item.mitre : [],
        name: typeof item.name === 'string' ? item.name : 'Custom playbook',
        description: typeof item.description === 'string' ? item.description : '',
        trigger: item.trigger || { severity: [], cooldown_seconds: 3600 },
        actions: Array.isArray(item.actions) ? item.actions : [],
        createdAt: item.createdAt || null,
      }))
  } catch {
    return []
  }
}

function persistCustom(list, storage) {
  if (!storage) return
  storage.setItem(CUSTOM_STORAGE_KEY, JSON.stringify(list))
}

export function saveCustomTemplate(draft, opts = {}, storage = typeof localStorage === 'undefined' ? null : localStorage) {
  const name = String(opts.name ?? draft?.name ?? '').trim()
  if (!name || !isValidPlaybookDraft(draft)) return null
  const existing = loadCustomTemplates(storage)
  const entry = {
    id: opts.id || `custom-${Date.now()}`,
    builtin: false,
    category: 'custom',
    intensity: opts.intensity || 'medium',
    mitre: [],
    name,
    description: String(opts.description ?? draft.description ?? ''),
    trigger: clone(draft.trigger || {}),
    actions: clone(draft.actions || []),
    createdAt: new Date().toISOString(),
  }
  persistCustom([entry, ...existing.filter((e) => e.id !== entry.id)], storage)
  return entry
}

export function deleteCustomTemplate(id, storage = typeof localStorage === 'undefined' ? null : localStorage) {
  const next = loadCustomTemplates(storage).filter((e) => e.id !== id)
  persistCustom(next, storage)
  return next
}

export function mergeCatalog(custom = []) {
  return [...BUILTIN_PLAYBOOKS, ...custom]
}

export function catalogHaystack(template, t) {
  const name = template.nameKey
    ? translate(t, template.nameKey, template.fallbackName || template.name || '')
    : (template.name || '')
  const description = template.descriptionKey
    ? translate(t, template.descriptionKey, template.fallbackDescription || template.description || '')
    : (template.description || '')
  const engines = Array.isArray(template.trigger?.engines) ? template.trigger.engines.join(' ') : ''
  const kinds = Array.isArray(template.actions) ? template.actions.map((a) => a.kind).join(' ') : ''
  return `${name} ${description} ${template.category || ''} ${template.id || ''} ${engines} ${kinds}`.toLowerCase()
}

export function filterCatalog(list, query = '', category = '', t) {
  const q = String(query || '').trim().toLowerCase()
  const cat = String(category || '').trim()
  return (list || []).filter((item) => {
    if (cat && item.category !== cat) return false
    if (!q) return true
    return catalogHaystack(item, t).includes(q)
  })
}

export function actionKindLabel(kind, t) {
  const entry = ACTION_KINDS.find((a) => a.kind === kind)
  if (!entry) return kind
  return translate(t, entry.labelKey, kind)
}
