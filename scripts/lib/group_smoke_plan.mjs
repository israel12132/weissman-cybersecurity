/** Shared one-engine-per-group smoke / findings E2E plan. */
export const GROUP_SMOKE_PLAN = [
  { group: 'recon', engine: 'recon', target: 'example.com' },
  { group: 'web', engine: 'jwt_attack', target: 'https://example.com' },
  { group: 'ai', engine: 'llm_jailbreak', target: 'https://example.com' },
  { group: 'cloud', engine: 'cloud_audit_evasion', target: 'https://example.com' },
  { group: 'ot', engine: 'iot_firmware', target: 'example.com' },
  { group: 'stealth', engine: 'antiforensics', target: 'https://example.com' },
  { group: 'crypto', engine: 'pki_tls', target: 'https://example.com' },
  { group: 'network', engine: 'bgp_dns_hijacking', target: 'example.com' },
  { group: 'supply_chain', engine: 'supply_chain', target: 'https://github.com/octocat/Hello-World' },
  { group: 'apt', engine: 'kill_chain', target: 'https://example.com' },
  { group: 'malware', engine: 'fileless_malware_engine', target: 'https://example.com' },
  { group: 'social', engine: 'spear_phishing_engine', target: 'https://example.com' },
  { group: 'mobile', engine: 'android_malware_engine', target: 'https://example.com' },
  { group: 'data', engine: 'dns_exfil_engine', target: 'https://example.com' },
]

/** Condensed plan for findings+risk E2E (one engine per major surface, bounded runtime). */
export const FINDINGS_E2E_PLAN = [
  { group: 'recon', engine: 'recon', target: 'example.com' },
  { group: 'web', engine: 'osint', target: 'https://example.com' },
  { group: 'network', engine: 'bgp_dns_hijacking', target: 'example.com' },
  { group: 'apt', engine: 'kill_chain', target: 'https://example.com' },
  { group: 'intel', engine: 'zero_day_radar', target: null },
  { group: 'timing', engine: 'microsecond_timing', target: 'https://example.com' },
]

export function extractHost(target) {
  if (!target) return ''
  try {
    return new URL(target).hostname
  } catch {
    return String(target)
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .trim()
  }
}

export function collectApprovedDomains(plan) {
  return [...new Set(plan.map((e) => extractHost(e.target)).filter(Boolean))].sort()
}
