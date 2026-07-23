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
//   * bgp_dns_hijacking — fans out to public DoH/UDP resolvers, crt.sh CT logs,
//     RDAP/RIPEstat and authoritative NS across ~45 phases with no overall time
//     budget. We disable autonomous mode and every fan-out/external probe (see
//     BGP_DNS_CI_PARAMS) so only the fast apex resolver-consensus + DNSSEC DoH
//     checks run, bounding total runtime to seconds instead of minutes.
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
const BGP_DNS_CI_PARAMS = {
  // The engine has NO overall wall-clock budget: total runtime is the sum of
  // ~45 external-network probes (multi-resolver DoH, DNSSEC, crt.sh CT-log
  // enumeration + per-subdomain takeover, RDAP, RIPEstat BGP/RPKI/IRR, UDP/53
  // cross-checks, TLS/HSTS/HTTP). On the sandboxed CI runner those reach slow or
  // unreachable third parties, and against example.com's huge CT footprint the
  // scan intermittently ran ~11 minutes — far past the E2E poll window ('job
  // timeout'). Tight per-op timeout/concurrency alone can't bound it because the
  // fan-out multiplies. So instead of throttling, disable the fan-out: turn OFF
  // autonomous mode (otherwise the adaptive plan re-enables probes from live
  // discovery) and switch off every external/fan-out check, keeping only the
  // fast apex resolver-consensus + DNSSEC checks over DoH (a couple of ~1.5s
  // requests). The engine still completes a real scan and drives the findings
  // pipeline; 0 persisted findings is an accepted terminal state for the smoke.
  autonomous_mode: false,
  force_all_probes: false,
  timeout_ms: 1500,
  concurrency: 8,
  max_ct_hosts: 0,
  // Fast DoH core — kept on.
  check_resolver_consensus: true,
  check_dnssec: true,
  // Fan-out / slow-external checks — off.
  check_ct: false,
  check_ct_discovery: false,
  check_takeover: false,
  check_discovered_tls: false,
  check_tls_identity: false,
  check_rpki: false,
  check_rpki_maxlength: false,
  check_bgp: false,
  check_bgp_visibility: false,
  check_routing_history: false,
  check_more_specific: false,
  check_irr: false,
  check_rdap: false,
  check_dane: false,
  check_udp_doh_cross: false,
  check_hsts: false,
  check_http_redirect: false,
  check_fcrdns: false,
  check_caa: false,
  check_caa_ct_cross: false,
  check_ns: false,
  check_ns_lame: false,
  check_glue: false,
  check_parent_ns: false,
  check_delegation_walk: false,
  check_auth_recursive: false,
  check_mx_origin: false,
  check_dmarc: false,
  check_spf_apex: false,
  check_soa: false,
  check_soa_serial: false,
  check_cds_cdnskey: false,
  check_orphan_ds: false,
  check_cname_chain: false,
  check_wildcard: false,
  check_aaaa: false,
  check_dual_stack: false,
  check_bogon: false,
  check_ttl: false,
  check_geo: false,
  check_baseline_delta: false,
  check_resolver_timing: false,
  check_dnssec_ad_divergence: false,
}
//   * pki_tls — performs LIVE OpenSSL handshakes to :443. The protocol matrix
//     (one handshake per SSLv3 / TLS 1.0-1.3) and especially cipher enumeration
//     (an iterative handshake per accepted suite) fire dozens of raw TCP
//     connects. On the sandboxed CI runner, direct outbound TCP to :443 is
//     intermittently slow/blocked (unlike HTTPS, which flows through the agent
//     proxy), so that fan-out ran ~6.4 min and blew the poll window ('job
//     timeout') even with CT/OCSP already disabled. Each connect is bounded by
//     connect_timeout(timeout_ms), so the fix is to cut the NUMBER of
//     handshakes to one: keep a single certificate-grab handshake (+ offline
//     posture scoring over it) and disable the multi-handshake enumeration and
//     every external DNS/HTTP/CT/OCSP probe. Worst case (a blocked connect) now
//     completes in ~timeout_ms with 0 findings instead of hanging; when :443 is
//     reachable the cert findings still drive the pipeline end-to-end.
const PKI_TLS_CI_PARAMS = {
  intensity: 'light',
  ports: [443],
  timeout_ms: 2000,
  port_budget_secs: 10,
  // Single cert-grab handshake + offline scoring — kept on.
  check_certificate: true,
  check_posture_score: true,
  // Multi-handshake enumeration + external (DNS/HTTP/CT/OCSP) probes — off.
  check_protocols: false,
  check_ciphers: false,
  check_forward_secrecy: false,
  check_vulnerabilities: false,
  check_chain_trust: false,
  check_hostname: false,
  check_ocsp: false,
  check_http_headers: false,
  check_security_headers: false,
  check_ct_logs: false,
  check_caa: false,
  check_dane: false,
}
//   * microsecond_timing — profiles latency by firing a baseline sweep plus a
//     heavy-payload sweep of SEQUENTIAL HTTP requests per URL. At its defaults
//     that is 100 baseline + 8 payloads × 50 samples = 500 requests per URL with
//     no concurrency and no wall-clock budget; against example.com through the
//     runner's egress each request is ~0.1-0.5s, so the single-URL scan ran
//     right at (and intermittently past) the E2E poll window ('job timeout').
//     Every knob below is read live from the scan body by the engine, so this is
//     pure request tuning — cut the baseline/payload sample counts, probe only 2
//     of the 8 payloads, cap the path fan-out to one URL, and set a hard 45s
//     wall-clock ceiling. Worst case now completes in well under a minute (~52
//     requests) with the same statistical pipeline, and the budget guarantees
//     termination regardless of egress latency.
const MICROSECOND_TIMING_CI_PARAMS = {
  timing_baseline_samples: 12,
  timing_payload_samples: 20,
  timing_payload_variants: 2,
  timing_max_urls: 1,
  timing_budget_secs: 45,
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
  { group: 'timing', engine: 'microsecond_timing', target: 'https://example.com', params: MICROSECOND_TIMING_CI_PARAMS },
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
