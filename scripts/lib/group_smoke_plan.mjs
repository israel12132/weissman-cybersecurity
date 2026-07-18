// Two engines in this plan reach *live third-party* infrastructure that a
// sandboxed CI runner cannot serve deterministically, so their runtime is
// unbounded relative to the E2E poll window:
//   * jwt_attack — harvests/forges tokens against the target and probes JWKS /
//     alg-confusion / SSRF endpoints. Against a scope with no live JWTs
//     (example.com) those loops find nothing yet fire dozens of outbound
//     requests at a fixed 10s client timeout; in CI they intermittently stall
//     past the poll window. We disable the live-probe loops (harvest / alg /
//     jwks / attack-paths) so the engine runs its deterministic offline
//     analysis and still exercises the full findings pipeline.
//   * bgp_dns_hijacking — fans out to public DoH/UDP resolvers, crt.sh CT logs
//     and authoritative NS across many phases (8s default per op). We pass a
//     tight timeout_ms + light intensity so every phase fails fast, bounding
//     total runtime to well under the poll window.
// Every engine's `job_params` are read live from the scan body via
// ArsenalConfig, so this is pure request tuning — no engine code changes.
const JWT_ATTACK_CI_PARAMS = {
  intensity: 'light',
  timeout_ms: 2500,
  harvest: false,
  test_alg_none: false,
  test_alg_confusion: false,
  check_jwks: false,
  attack_paths: false,
}
const BGP_DNS_CI_PARAMS = { intensity: 'light', timeout_ms: 2000, concurrency: 8 }
//   * pki_tls — TLS posture scan. The core cert/protocol/cipher findings come
//     from the port-443 handshake, but the engine also fetches crt.sh CT logs
//     (fixed 10s client, can hang) and OCSP, and scans a port budget — on the
//     slow CI runner this intermittently pushed total runtime past the poll
//     window (recurring 'job timeout' victim). Bound it: light intensity +
//     tight handshake timeout + skip the slow external CT/OCSP fetches + a hard
//     port budget. The TLS handshake to :443 (and its ~dozen findings) is
//     unaffected, so the findings pipeline is still exercised end-to-end.
const PKI_TLS_CI_PARAMS = {
  intensity: 'light',
  timeout_ms: 2500,
  check_ct_logs: false,
  check_ocsp: false,
  port_budget_secs: 15,
}

/** Shared one-engine-per-group smoke / findings E2E plan. */
export const GROUP_SMOKE_PLAN = [
  { group: 'recon', engine: 'recon', target: 'example.com' },
  { group: 'web', engine: 'jwt_attack', target: 'https://example.com', params: JWT_ATTACK_CI_PARAMS },
  { group: 'ai', engine: 'llm_jailbreak', target: 'https://example.com' },
  { group: 'cloud', engine: 'cloud_audit_evasion', target: 'https://example.com' },
  { group: 'ot', engine: 'iot_firmware', target: 'example.com' },
  { group: 'stealth', engine: 'antiforensics', target: 'https://example.com' },
  { group: 'crypto', engine: 'pki_tls', target: 'https://example.com', params: PKI_TLS_CI_PARAMS },
  { group: 'network', engine: 'bgp_dns_hijacking', target: 'example.com', params: BGP_DNS_CI_PARAMS },
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
  { group: 'network', engine: 'bgp_dns_hijacking', target: 'example.com', params: BGP_DNS_CI_PARAMS },
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
