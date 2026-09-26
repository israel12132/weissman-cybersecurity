#!/usr/bin/env node
/**
 * generate_openapi.mjs — derive the OpenAPI path inventory from the axum route table.
 *
 * Source of truth: fingerprint_engine/src/http/serve_route_groups.rs (the `.route(...)`
 * registrations) plus the PUBLIC_ROUTES allow-list in fingerprint_engine/src/http/serve.rs.
 *
 * Emits (committed, drift-checked in CI):
 *   • fingerprint_engine/src/openapi_paths.generated.json  — merged into the served spec by
 *     `api_openapi_spec` via include_str!. Contains { x-generated, tags, paths }.
 *   • docs/openapi/ROUTE_INVENTORY.md                      — human-readable route table.
 *
 * Usage:
 *   node scripts/generate_openapi.mjs            # (re)write the artifacts
 *   node scripts/generate_openapi.mjs --check    # fail (exit 1) if artifacts are stale
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = process.cwd()
const ROUTES_RS = join(ROOT, 'fingerprint_engine/src/http/serve_route_groups.rs')
const SERVE_RS = join(ROOT, 'fingerprint_engine/src/http/serve.rs')
const OUT_JSON = join(ROOT, 'fingerprint_engine/src/openapi_paths.generated.json')
const OUT_MD = join(ROOT, 'docs/openapi/ROUTE_INVENTORY.md')

/** Scan `.route("...", <expr>)` calls with a paren-balanced reader that ignores string bodies. */
function extractRoutes(src) {
  const routes = []
  const needle = '.route('
  let i = 0
  while ((i = src.indexOf(needle, i)) !== -1) {
    let k = i + needle.length
    let depth = 1
    let inStr = false
    let strCh = ''
    const start = k
    while (k < src.length && depth > 0) {
      const c = src[k]
      if (inStr) {
        if (c === '\\') { k += 2; continue }
        if (c === strCh) inStr = false
      } else if (c === '"' || c === "'") {
        inStr = true
        strCh = c
      } else if (c === '(') depth++
      else if (c === ')') depth--
      if (depth === 0) break
      k++
    }
    const arg = src.slice(start, k)
    i = k + 1
    const pathMatch = arg.match(/"((?:[^"\\]|\\.)*)"/)
    if (!pathMatch) continue
    const path = pathMatch[1]
    // Only the leading method-router builders (get(...).post(...)) — take unique ones.
    const methods = []
    for (const m of arg.matchAll(/\b(get|post|put|patch|delete)\s*\(/g)) {
      if (!methods.includes(m[1])) methods.push(m[1])
    }
    // primary handler fn name for x-handler (first ident inside the first builder call)
    const handlerMatch = arg.match(/\b(?:get|post|put|patch|delete)\s*\(\s*([A-Za-z0-9_:]+)/)
    const handler = handlerMatch ? handlerMatch[1].split('::').pop() : null
    if (methods.length === 0) {
      throw new Error(`route "${path}" has no HTTP method builder — parser drift`)
    }
    routes.push({ path, methods, handler })
  }
  return routes
}

/** Parse the PUBLIC_ROUTES table so unauthenticated ops get `security: []`. */
function extractPublicRoutes(src) {
  const start = src.indexOf('static PUBLIC_ROUTES')
  if (start === -1) return new Set()
  const open = src.indexOf('[', start)
  let k = open + 1
  let depth = 1
  while (k < src.length && depth > 0) {
    if (src[k] === '[') depth++
    else if (src[k] === ']') depth--
    if (depth === 0) break
    k++
  }
  const body = src.slice(open + 1, k)
  const set = new Set()
  for (const m of body.matchAll(/Method::(GET|POST|PUT|PATCH|DELETE)\s*,\s*"((?:[^"\\]|\\.)*)"/g)) {
    set.add(`${m[1]} ${m[2]}`)
  }
  return set
}

/** axum `:param` -> `{param}`, `*rest` -> `{rest}`. */
function toOpenApiPath(p) {
  return p
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) return `{${seg.slice(1)}}`
      if (seg.startsWith('*')) return `{${seg.slice(1)}}`
      return seg
    })
    .join('/')
}

const TAG_RULES = [
  // Most specific first. Match = exact path OR path starts with the key.
  ['/api/threat-analysis', 'Risk & Exposure'],
  ['/api/threat-intel', 'Threat Intel'],
  ['/api/threat-ingest', 'Threat Intel'],
  ['/api/threat', 'Threat Intel'],
  ['/api/attack', 'Risk & Exposure'],
  ['/api/posture', 'Risk & Exposure'],
  ['/api/remediation', 'Risk & Exposure'],
  ['/api/executive', 'Risk & Exposure'],
  ['/api/risk-graph', 'Risk & Exposure'],
  ['/api/risk', 'Risk & Exposure'],
  ['/api/financial-risk', 'Risk & Exposure'],
  ['/api/battlespace', 'Risk & Exposure'],
  ['/api/auth', 'Auth & Identity'],
  ['/api/mfa', 'Auth & Identity'],
  ['/api/login', 'Auth & Identity'],
  ['/api/logout', 'Auth & Identity'],
  ['/api/sso', 'Auth & Identity'],
  ['/api/scim', 'Auth & Identity'],
  ['/api/identity', 'Auth & Identity'],
  ['/api/account', 'Auth & Identity'],
  ['/api/tenant', 'Auth & Identity'],
  ['/api/gdpr', 'Auth & Identity'],
  ['/api/agents', 'Agents'],
  ['/api/agent', 'Agents'],
  ['/install/', 'Agents'],
  ['/ws/agent', 'Agents'],
  ['/api/findings', 'Findings'],
  ['/api/scan-finding-spine', 'Findings'],
  ['/api/clients', 'Clients'],
  ['/api/report', 'Reporting & Evidence'],
  ['/api/export', 'Reporting & Evidence'],
  ['/api/board-pack', 'Reporting & Evidence'],
  ['/api/evidence', 'Reporting & Evidence'],
  ['/api/engagements', 'Reporting & Evidence'],
  ['/api/roe', 'Reporting & Evidence'],
  ['/api/verify-audit', 'Reporting & Evidence'],
  ['/api/forensic', 'Reporting & Evidence'],
  ['/api/compliance', 'Compliance'],
  ['/api/sbom', 'Compliance'],
  ['/api/market-readiness', 'Compliance'],
  ['/api/enterprise', 'Compliance'],
  ['/api/first-mover', 'Compliance'],
  ['/api/arsenal', 'Arsenal & Engines'],
  ['/api/engines', 'Arsenal & Engines'],
  ['/api/scans', 'Arsenal & Engines'],
  ['/api/scan', 'Arsenal & Engines'],
  ['/api/discovery', 'Arsenal & Engines'],
  ['/api/fuzz', 'Arsenal & Engines'],
  ['/api/edge-fuzz', 'Arsenal & Engines'],
  ['/api/oast', 'Arsenal & Engines'],
  ['/api/poe-scan', 'Arsenal & Engines'],
  ['/api/pipeline', 'Arsenal & Engines'],
  ['/api/timing-scan', 'Arsenal & Engines'],
  ['/api/dag', 'Arsenal & Engines'],
  ['/api/template-engine', 'Arsenal & Engines'],
  ['/api/payload-sync', 'Arsenal & Engines'],
  ['/api/latency-probe', 'Arsenal & Engines'],
  ['/api/intel', 'Threat Intel'],
  ['/api/ioc', 'Threat Intel'],
  ['/api/ndr', 'Threat Intel'],
  ['/api/telemetry', 'Threat Intel'],
  ['/api/search', 'Threat Intel'],
  ['/api/playbooks', 'SOAR & Playbooks'],
  ['/api/soar', 'SOAR & Playbooks'],
  ['/api/campaigns', 'SOAR & Playbooks'],
  ['/api/adversary', 'SOAR & Playbooks'],
  ['/api/soc', 'SOC & Detection'],
  ['/api/ueba', 'SOC & Detection'],
  ['/api/itdr', 'SOC & Detection'],
  ['/api/alerts', 'SOC & Detection'],
  ['/api/containment', 'SOC & Detection'],
  ['/api/deception', 'SOC & Detection'],
  ['/api/honey-routing', 'SOC & Detection'],
  ['/api/cnapp', 'Cloud & Infra Posture'],
  ['/api/cem-dago', 'Cloud & Infra Posture'],
  ['/api/vngfw', 'Cloud & Infra Posture'],
  ['/api/ot-ics', 'Cloud & Infra Posture'],
  ['/api/mobile-security', 'Cloud & Infra Posture'],
  ['/api/crypto', 'Cloud & Infra Posture'],
  ['/api/edge-swarm', 'Cloud & Infra Posture'],
  ['/api/ceo', 'Governance & Executive'],
  ['/api/council', 'Governance & Executive'],
  ['/api/sovereign-defense', 'Governance & Executive'],
  ['/api/sovereign', 'Governance & Executive'],
  ['/api/supreme-brain', 'Governance & Executive'],
  ['/api/dashboard', 'Governance & Executive'],
  ['/api/portfolio', 'Governance & Executive'],
  ['/api/command-center', 'Governance & Executive'],
  ['/ws/command-center', 'Governance & Executive'],
  ['/api/heal', 'Self-Healing & Hardening'],
  ['/api/self-improve', 'Self-Healing & Hardening'],
  ['/api/baseline', 'Self-Healing & Hardening'],
  ['/api/elite-hardening', 'Self-Healing & Hardening'],
  ['/api/security', 'Self-Healing & Hardening'],
  ['/api/stealthy-persistence-evasion', 'Stealth & Red Team'],
  ['/api/stealth', 'Stealth & Red Team'],
  ['/api/llm-ultra-guard', 'Stealth & Red Team'],
  ['/api/ai-redteam', 'Stealth & Red Team'],
  ['/api/swarm', 'Stealth & Red Team'],
  ['/api/admin', 'Admin & Platform'],
  ['/api/system', 'Admin & Platform'],
  ['/api/config', 'Admin & Platform'],
  ['/api/rate-limits', 'Admin & Platform'],
  ['/api/quota', 'Admin & Platform'],
  ['/api/jobs', 'Admin & Platform'],
  ['/api/metrics', 'Admin & Platform'],
  ['/api/health', 'Admin & Platform'],
  ['/api/ready', 'Admin & Platform'],
  ['/api/billing', 'Billing & Onboarding'],
  ['/api/onboarding', 'Billing & Onboarding'],
  ['/api/brand', 'Billing & Onboarding'],
  ['/api/integrations', 'Integrations & Webhooks'],
  ['/api/webhooks', 'Integrations & Webhooks'],
  ['/api/messages', 'Integrations & Webhooks'],
  ['/hooks/', 'Integrations & Webhooks'],
  ['/api/audit-logs', 'Audit'],
  ['/api/audit', 'Audit'],
  ['/api/competitive', 'Competitive Intel'],
  ['/api/public', 'Public'],
  ['/api/ask', 'Public'],
  ['/status', 'Public'],
  ['/api/docs', 'API Docs'],
  ['/api/openapi', 'API Docs'],
  ['/api/general', 'Admin & Platform'],
  ['/api/v1/', 'v1 (stable)'],
  ['/ws/', 'WebSocket'],
]

function tagFor(path) {
  for (const [key, tag] of TAG_RULES) {
    if (path === key || path.startsWith(key)) return tag
  }
  return 'Other'
}

function operationId(method, oaPath) {
  const slug = oaPath
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
  return `${method}_${slug}`
}

function pathParams(oaPath) {
  const params = []
  for (const m of oaPath.matchAll(/\{([^}]+)\}/g)) {
    params.push({
      name: m[1],
      in: 'path',
      required: true,
      schema: { type: 'string' },
    })
  }
  return params
}

function build() {
  const routesSrc = readFileSync(ROUTES_RS, 'utf8')
  const serveSrc = readFileSync(SERVE_RS, 'utf8')
  const routes = extractRoutes(routesSrc)
  const publicSet = extractPublicRoutes(serveSrc)

  const paths = {}
  const tagSet = new Set()
  const seenOpIds = new Map()
  let opCount = 0
  const inventory = []

  for (const r of routes.sort((a, b) => a.path.localeCompare(b.path))) {
    const oaPath = toOpenApiPath(r.path)
    const tag = tagFor(r.path)
    tagSet.add(tag)
    if (!paths[oaPath]) paths[oaPath] = {}
    const params = pathParams(oaPath)
    for (const method of r.methods) {
      const opKey = `${method.toUpperCase()} ${r.path}`
      const isPublic = publicSet.has(opKey)
      let opId = operationId(method, oaPath)
      const dupN = (seenOpIds.get(opId) || 0) + 1
      seenOpIds.set(opId, dupN)
      if (dupN > 1) opId = `${opId}_${dupN}`
      const op = {
        tags: [tag],
        summary: `${method.toUpperCase()} ${oaPath}`,
        operationId: opId,
        responses: {
          200: { description: 'Successful response' },
          400: { description: 'Bad request' },
          ...(isPublic ? {} : { 401: { description: 'Unauthenticated' } }),
        },
      }
      if (params.length) op.parameters = params
      if (r.handler) op['x-handler'] = r.handler
      if (isPublic) op.security = []
      paths[oaPath][method] = op
      opCount++
      inventory.push({ method: method.toUpperCase(), path: oaPath, tag, handler: r.handler || '', public: isPublic })
    }
  }

  const tags = [...tagSet].sort().map((name) => ({ name }))

  const doc = {
    'x-generated': {
      by: 'scripts/generate_openapi.mjs',
      source: 'fingerprint_engine/src/http/serve_route_groups.rs',
      note: 'DO NOT EDIT BY HAND. Run: node scripts/generate_openapi.mjs',
      routeCount: routes.length,
      operationCount: opCount,
    },
    tags,
    paths,
  }
  return { doc, inventory, routeCount: routes.length, opCount }
}

function renderMarkdown(inventory, routeCount, opCount) {
  const byTag = {}
  for (const e of inventory) (byTag[e.tag] ||= []).push(e)
  let md = '# Weissman API — Route Inventory (generated)\n\n'
  md += '> Generated by `scripts/generate_openapi.mjs` from the axum route table. Do not edit by hand.\n\n'
  md += `**${routeCount}** registered routes · **${opCount}** operations · **${Object.keys(byTag).length}** domains.\n\n`
  md += 'See `docs/API_VERSIONING.md` for the versioning & deprecation policy. The live spec is at `GET /api/openapi.json` (Swagger UI at `/api/docs`).\n\n'
  for (const tag of Object.keys(byTag).sort()) {
    md += `## ${tag}\n\n`
    md += '| Method | Path | Auth | Handler |\n|---|---|---|---|\n'
    for (const e of byTag[tag].sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method))) {
      md += `| ${e.method} | \`${e.path}\` | ${e.public ? 'public' : 'JWT'} | \`${e.handler}\` |\n`
    }
    md += '\n'
  }
  return md
}

const CHECK = process.argv.includes('--check')
const { doc, inventory, routeCount, opCount } = build()
const jsonOut = JSON.stringify(doc, null, 2) + '\n'
const mdOut = renderMarkdown(inventory, routeCount, opCount)

if (CHECK) {
  let stale = []
  const cur = existsSync(OUT_JSON) ? readFileSync(OUT_JSON, 'utf8') : ''
  if (cur !== jsonOut) stale.push(OUT_JSON)
  const curMd = existsSync(OUT_MD) ? readFileSync(OUT_MD, 'utf8') : ''
  if (curMd !== mdOut) stale.push(OUT_MD)
  if (stale.length) {
    console.error('::error::OpenAPI artifacts are stale — a route was added/changed without regenerating.')
    console.error('Run: node scripts/generate_openapi.mjs')
    for (const f of stale) console.error('  stale: ' + f)
    process.exit(1)
  }
  console.log(`OpenAPI drift check OK — ${routeCount} routes / ${opCount} operations in sync.`)
  process.exit(0)
}

mkdirSync(join(ROOT, 'docs/openapi'), { recursive: true })
writeFileSync(OUT_JSON, jsonOut)
writeFileSync(OUT_MD, mdOut)
console.log(`Wrote ${OUT_JSON} (${routeCount} routes, ${opCount} operations)`)
console.log(`Wrote ${OUT_MD}`)
