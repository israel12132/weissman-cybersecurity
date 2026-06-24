/**
 * Route → primary engine id for command-center scan hubs.
 * Used by PageShell to auto-apply AgentRequiredGate (no mock data when agent offline).
 */

/** Exact pathname (basename-relative, no trailing slash) → engine id */
export const ROUTE_ENGINE_ID = {
  '/attack-surface': 'asm',
  '/cache-posture': 'cache_poisoning',
  '/cicd-security': 'cicd_pipeline',
  '/cloud-posture': 'cloud_posture',
  '/detection-surface': 'edr_evasion',
  '/digital-twin': 'digital_twin',
  '/dns-posture': 'bgp_dns_hijacking',
  '/email-posture': 'email_dns_posture',
  '/file-upload-lab': 'file_upload',
  '/graphql-security': 'graphql_attack',
  '/http-smuggling': 'http_smuggling',
  '/iac-security': 'iac_misconfig',
  '/identity-security': 'oauth_oidc',
  '/jwt-lab': 'jwt_attack',
  '/kerberos-security': 'kerberoasting',
  '/mobile-security': 'mobile_attack',
  '/nexus-swarm': 'nexus_sovereign_swarm',
  '/ot-ics': 'scada_ics',
  '/password-spray': 'password_spray',
  '/pqc-radar': 'pqc_scanner',
  '/saml-security': 'saml_attack',
  '/serverless-security': 'serverless_attack',
  '/smb-netbios': 'smb_netbios',
  '/tls-posture': 'pki_tls',
  '/transport-security': 'mtls_grpc',
  '/waf-bypass': 'waf_bypass',
  '/websocket-security': 'websocket_attack',
  '/engines/osint': 'osint',
}

/** Prefix routes for nested engine profiles */
export const ROUTE_ENGINE_ID_PREFIX = [
  { prefix: '/engines/top-tier/', engineFromParam: true },
  { prefix: '/engines/business/', engineFromParam: true },
  { prefix: '/engines/', engineFromParam: true },
]

/**
 * Resolve engine id for current pathname (supports /command-center basename).
 * Returns null when the route is not tied to a single engine hub.
 */
export function resolveRouteEngineId(pathname) {
  if (!pathname) return null
  let p = pathname
  if (p.startsWith('/command-center')) {
    p = p.slice('/command-center'.length) || '/'
  }
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)

  if (ROUTE_ENGINE_ID[p]) return ROUTE_ENGINE_ID[p]

  for (const rule of ROUTE_ENGINE_ID_PREFIX) {
    if (!p.startsWith(rule.prefix)) continue
    const tail = p.slice(rule.prefix.length).split('/')[0]
    if (tail && rule.engineFromParam) return tail
  }

  return null
}
