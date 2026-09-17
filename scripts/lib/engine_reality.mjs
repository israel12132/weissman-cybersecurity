// Shared engine-reality classification — the single source of truth for "what each catalog
// engine ID actually is", derived directly from source (no estimates). Both
// `engine_reality_audit.mjs` (the CI reality gate) and `engine_coverage_accuracy_report.mjs`
// (the breadth + accuracy proof) consume this module so the two can never disagree.
//
// Classification buckets:
//   real_probe       : canonical engine with a live dispatch arm whose implementation reaches
//                      real network/host I/O (HTTP/TCP/UDP/DNS/TLS), directly or via a helper it
//                      calls — proven by static call-graph reachability from source.
//   advisory_only    : canonical engine with a dispatch arm whose implementation performs NO live
//                      network I/O — it analyses already-ingested telemetry, correlates existing
//                      findings, or returns agent-required / advisory guidance. Not a live probe,
//                      so it must not inflate the "live probes" headline. Only assigned when the
//                      impl fn body is found AND provably reaches no network primitive; any arm we
//                      cannot resolve, or that probes on even one path (a hybrid), stays real_probe.
//   alias            : retag that resolves to another canonical engine (same detection logic)
//   agent_required   : remote-impossible; returns an info finding pointing to the endpoint agent
//   special          : routed via a non-dispatch path (async job / synthesis)
//   no_path          : in the catalog but with no execution path (must be ZERO; CI-gated)

import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const SPECIAL = new Set([])

// ── Network-reachability detector (advisory_only classification) ────────────────────────────────
// A dispatch arm is a *live probe* only if its implementation function can reach a real network
// primitive. We prove this by parsing every Rust source module (of the engine crate and the two
// sibling crates it delegates into), building a per-module function table plus its `use`-imports,
// and following calls — same-module helpers, `crate::`/cross-crate `MOD::fn(...)` delegations, and
// imported bare names — until a network primitive is hit. Over-approximating "what is a call"
// only ever keeps an arm in real_probe, so the detector errs on the side of NOT reclassifying
// (conservative): an arm becomes advisory_only only when its body is found and provably reaches no
// network primitive. Everything here is derived from source — no hand-maintained lists.

// Crate source roots scanned for the call graph (skipped silently if absent).
const NET_SCAN_DIRS = [
  'fingerprint_engine/src',
  'backend/weissman-engines/src',
  'backend/weissman-core/src',
]

// Leaf network helpers exported by engine_probes.rs (bare-name calls into real I/O).
const NET_HELPERS = [
  'http_client', 'http1_client', 'http2_client',
  'http_get', 'http_get_with_headers', 'http_get_retry',
  'http_post_json', 'http_post_json_with_headers', 'http_post_bytes_with_headers',
  'http_method_with_headers',
  'tcp_open', 'tcp_banner', 'tcp_probe_response', 'tcp_scan',
  'udp_probe_response',
  'dns_a', 'dns_aaaa', 'dns_txt', 'dns_mx', 'dns_cname', 'dns_caa', 'dns_tlsa', 'dns_a_min_ttl',
  'tls_cert_summary', 'tls_cert_details',
  'probe_paths_concurrent', 'fingerprint_stack',
]
const NET_HELPER_RE = new RegExp(`\\b(${NET_HELPERS.join('|')})\\s*\\(`)
// Raw primitives that are network I/O no matter which helper wraps them.
const RAW_NET_RE = /\breqwest\b|\bTcpStream\b|\bUdpSocket\b|tokio::net|\bhickory|lookup_ip|lookup_host|\.send\(\)\s*\.await|scan_http_client|outbound_http/
const QUAL_CALL_RE = /\b([A-Za-z_][A-Za-z0-9_]*)::([a-z_][A-Za-z0-9_]*)\s*\(/g
const BARE_CALL_RE = /(?<![.:\w])([a-z_][A-Za-z0-9_]*)\s*\(/g

// Blank out comments, string/byte/raw-string and char literals so brace matching and call
// extraction are not fooled by punctuation inside literals (e.g. `contains('{')`).
function cleanRustSource(src) {
  let out = ''
  let i = 0
  const n = src.length
  while (i < n) {
    const c = src[i]
    const c2 = src[i + 1]
    if (c === '/' && c2 === '/') { while (i < n && src[i] !== '\n') i += 1; continue }
    if (c === '/' && c2 === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i += 1; i += 2; continue }
    if (c === 'r' && (c2 === '"' || c2 === '#')) {
      let j = i + 1
      let hashes = 0
      while (src[j] === '#') { hashes += 1; j += 1 }
      if (src[j] === '"') {
        const close = `"${'#'.repeat(hashes)}`
        const idx = src.indexOf(close, j + 1)
        i = idx < 0 ? n : idx + close.length
        out += ' '
        continue
      }
    }
    if (c === 'b' && c2 === '"') { i += 2; while (i < n && !(src[i] === '"' && src[i - 1] !== '\\')) i += 1; i += 1; out += ' '; continue }
    if (c === '"') {
      i += 1
      while (i < n) { if (src[i] === '\\') { i += 2; continue } if (src[i] === '"') { i += 1; break } i += 1 }
      out += ' '
      continue
    }
    if (c === "'") {
      const j = i + 1
      if (src[j] === '\\') { let k = j + 1; while (k < n && src[k] !== "'") k += 1; i = k + 1; out += ' '; continue }
      if (src[j] && src[j + 1] === "'") { i = j + 2; out += ' '; continue }
      // otherwise a lifetime (e.g. 'static) — keep the quote and continue normally
    }
    out += c
    i += 1
  }
  return out
}

function walkRustFiles(dir) {
  const out = []
  let entries
  try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return out }
  for (const e of entries) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walkRustFiles(p))
    else if (/\.(rs|inc)$/.test(e.name)) out.push(p)
  }
  return out
}

// Module name = the top-level dir under src (so a dir module's sub-files share one scope), else the
// file basename. This matches how `use crate::MOD::…` and `crate::MOD::fn` name a module's scope.
function moduleNameFor(file, srcRoot) {
  const rel = path.relative(srcRoot, file)
  const parts = rel.split(path.sep)
  return parts.length === 1 ? parts[0].replace(/\.(rs|inc)$/, '') : parts[0]
}

function extractModuleFns(text) {
  const map = new Map()
  const re = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(/g
  let m
  while ((m = re.exec(text)) !== null) {
    const open = text.indexOf('{', m.index)
    if (open < 0) continue
    if (text.slice(m.index + m[0].length, open).includes(';')) continue // trait sig / fn-pointer type
    let depth = 0
    for (let j = open; j < text.length; j += 1) {
      const ch = text[j]
      if (ch === '{') depth += 1
      else if (ch === '}') {
        depth -= 1
        if (depth === 0) {
          const body = text.slice(open + 1, j)
          map.set(m[1], map.has(m[1]) ? `${map.get(m[1])}\n${body}` : body)
          break
        }
      }
    }
  }
  return map
}

function parseModuleUses(text) {
  const map = new Map()
  const globs = []
  const re = /\buse\s+((?:crate|super|self|[A-Za-z_][A-Za-z0-9_]*))((?:::[A-Za-z_][A-Za-z0-9_]*)*)\s*(::\{[^}]*\}|::\*)?\s*;/g
  let m
  while ((m = re.exec(text)) !== null) {
    const segs = [m[1], ...(m[2] || '').split('::').filter(Boolean)]
    const tail = m[3] || ''
    if (tail.startsWith('::{')) {
      const srcMod = segs[segs.length - 1]
      for (let item of tail.slice(3, -1).split(',')) {
        item = item.trim()
        if (!item || item === 'self') continue
        const asM = item.match(/^([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$/)
        if (asM) { map.set(asM[2], srcMod); continue }
        const nm = item.match(/^([A-Za-z_][A-Za-z0-9_]*)$/)
        if (nm) map.set(nm[1], srcMod)
      }
    } else if (tail === '::*') {
      globs.push(segs[segs.length - 1])
    } else {
      const name = segs[segs.length - 1]
      const srcMod = segs[segs.length - 2]
      if (name && srcMod && /^[a-z_]/.test(name)) map.set(name, srcMod)
    }
  }
  return { map, globs }
}

// Build the reachability handle: `implReachesNet("MOD::FN")` returns true (reaches network I/O),
// false (impl fn found and provably reaches none), or null (impl fn not resolvable — caller keeps
// real_probe, since we cannot prove advisory).
function buildNetReachability(root) {
  const moduleText = new Map()
  for (const rel of NET_SCAN_DIRS) {
    const abs = path.join(root, rel)
    for (const f of walkRustFiles(abs)) {
      const mod = moduleNameFor(f, abs)
      let cleaned = ''
      try { cleaned = cleanRustSource(fs.readFileSync(f, 'utf8')) } catch { cleaned = '' }
      moduleText.set(mod, `${moduleText.get(mod) || ''}\n${cleaned}`)
    }
  }
  const moduleFns = new Map()
  const useMap = new Map()
  const globMap = new Map()
  for (const [mod, text] of moduleText) {
    moduleFns.set(mod, extractModuleFns(text))
    const { map, globs } = parseModuleUses(text)
    useMap.set(mod, map)
    globMap.set(mod, globs)
  }

  const bodyHasDirectNet = (body) => RAW_NET_RE.test(body) || NET_HELPER_RE.test(body)
  const memo = new Map()
  function reachesNet(mod, fn, seen) {
    const key = `${mod}::${fn}`
    if (memo.has(key)) return memo.get(key)
    if (seen.has(key)) return false
    seen.add(key)
    const fns = moduleFns.get(mod)
    const body = fns ? fns.get(fn) : null
    if (body == null) return false // unresolved — treat as non-net for propagation; top level keeps real_probe
    if (bodyHasDirectNet(body)) { memo.set(key, true); return true }
    let m
    QUAL_CALL_RE.lastIndex = 0
    while ((m = QUAL_CALL_RE.exec(body)) !== null) {
      if (reachesNet(m[1], m[2], seen)) { memo.set(key, true); return true }
    }
    BARE_CALL_RE.lastIndex = 0
    const bare = new Set()
    while ((m = BARE_CALL_RE.exec(body)) !== null) bare.add(m[1])
    const um = useMap.get(mod) || new Map()
    const gm = globMap.get(mod) || []
    for (const name of bare) {
      if (name === fn) continue
      if (fns && fns.has(name)) { if (reachesNet(mod, name, seen)) { memo.set(key, true); return true }; continue }
      if (um.has(name)) { if (reachesNet(um.get(name), name, seen)) { memo.set(key, true); return true }; continue }
      for (const g of gm) {
        const gf = moduleFns.get(g)
        if (gf && gf.has(name) && reachesNet(g, name, seen)) { memo.set(key, true); return true }
      }
    }
    memo.set(key, false)
    return false
  }

  return function implReachesNet(impl) {
    if (!impl || !impl.includes('::')) return null
    const parts = impl.split('::')
    const mod = parts[0]
    const fn = parts[parts.length - 1]
    const fns = moduleFns.get(mod)
    if (!fns || !fns.has(fn)) return null // impl fn not found — cannot prove advisory
    return reachesNet(mod, fn, new Set())
  }
}

function extractCriticalInfraIds(text) {
  const match = text.match(/pub const ENGINE_IDS: &\[&str\] = &\[(.*?)\];/s)
  if (!match) return new Set()
  return new Set([...match[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]))
}

function extractArray(name, text) {
  const m = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!m) throw new Error(`Missing array: ${name}`)
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

function extractResolveMap(text) {
  const start = text.indexOf('pub fn resolve_engine_id')
  const end = text.indexOf('pub fn is_engine_alias', start)
  const chunk = text.slice(start, text.lastIndexOf('}', end) + 1)
  const map = new Map()
  const pattern = /"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>\s*(?:\{\s*)?"([^"]+)"/gs
  for (const m of chunk.matchAll(pattern)) {
    map.set(m[1], m[3])
    for (const a of m[2].matchAll(/"([^"]+)"/g)) map.set(a[1], m[3])
  }
  return map
}

// Map each dispatch id -> implementation function (module::fn). Arms may union several ids.
function extractDispatchImpl(text) {
  const start = text.indexOf('match canonical {')
  const end = text.lastIndexOf('_ => EngineResult::')
  const chunk = text.slice(start, end)
  const armStart = /\n\s*"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>/g
  const matches = [...chunk.matchAll(armStart)]
  const idToImpl = new Map()
  for (let i = 0; i < matches.length; i += 1) {
    const m = matches[i]
    const ids = [m[1], ...[...m[2].matchAll(/"([^"]+)"/g)].map((a) => a[1])]
    const bodyStart = m.index + m[0].length
    const bodyEnd = i + 1 < matches.length ? matches[i + 1].index : chunk.length
    const body = chunk.slice(bodyStart, bodyEnd)
    const fn = body.match(/crate::([A-Za-z0-9_]+)::([A-Za-z0-9_]+)/)
    const impl = fn ? `${fn[1]}::${fn[2]}` : '(inline)'
    for (const id of ids) idToImpl.set(id, impl)
  }
  return idToImpl
}

/**
 * Load and classify every engine directly from source.
 * @param {string} root Repository root.
 * @returns classification handles: id sets/maps plus `classify(id)`, `implFor(id)`,
 *          and the frontend registry (with group/mitre metadata).
 */
export async function loadEngineReality(root) {
  const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
  const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
  const agentAgentRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine_agent.rs'), 'utf8')
  const criticalInfraRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/critical_infra/mod.rs'), 'utf8')
  const frontendModule = await import(
    pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href
  )

  const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
  const agentRequired = new Set(extractArray('AGENT_REQUIRED_ENGINES', agentAgentRs))
  const resolveMap = extractResolveMap(engineRs)
  const dispatchImpl = extractDispatchImpl(dispatchRs)
  const dispatchIds = new Set(dispatchImpl.keys())
  const criticalInfraIds = extractCriticalInfraIds(criticalInfraRs)
  const registry = frontendModule.ENGINES_REGISTRY
  const frontendIds = registry.map((e) => e.id)

  // Prove which dispatch arms are live probes vs advisory-only via source call-graph reachability.
  // A dispatch id is advisory_only when its implementation is resolvable AND reaches no network
  // primitive. critical_infra engines are a verified live-probe subsystem (every arm does a real
  // TCP/HTTP probe, with agent guidance only as a supplement) and stay real_probe.
  const implReachesNet = buildNetReachability(root)
  const advisoryOnlyIds = new Set()
  for (const id of dispatchIds) {
    if (implReachesNet(dispatchImpl.get(id)) === false) advisoryOnlyIds.add(id)
  }

  function classify(id) {
    if (agentRequired.has(id)) return 'agent_required'
    const canon = resolveMap.get(id) || id
    if (canon !== id) return 'alias'
    if (criticalInfraIds.has(id)) return 'real_probe'
    if (dispatchIds.has(id)) return advisoryOnlyIds.has(id) ? 'advisory_only' : 'real_probe'
    if (SPECIAL.has(id)) return 'special'
    return 'no_path'
  }

  function implFor(id) {
    return criticalInfraIds.has(id)
      ? 'critical_infra::dispatch'
      : dispatchImpl.get(id) || '(unknown)'
  }

  function tally(ids) {
    const buckets = {
      real_probe: [],
      advisory_only: [],
      alias: [],
      agent_required: [],
      special: [],
      no_path: [],
    }
    for (const id of ids) buckets[classify(id)].push(id)
    return buckets
  }

  return {
    productionIds,
    frontendIds,
    registry,
    agentRequired,
    resolveMap,
    dispatchImpl,
    dispatchIds,
    criticalInfraIds,
    advisoryOnlyIds,
    classify,
    implFor,
    tally,
  }
}
