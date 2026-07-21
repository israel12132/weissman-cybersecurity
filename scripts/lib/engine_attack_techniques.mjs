// Code-grounded ATT&CK technique extraction (shared).
//
// Every engine implementation tags the findings it emits with `mitre: "Txxxx"` (and kill-chain
// `mitre_path` arrays). Those T-codes are the techniques the engine ACTUALLY performs — the
// authoritative, code-grounded source (not descriptions). This resolves each engine to its
// dispatch impl function, extracts the T-codes in that function (following 1-hop delegation only
// into helpers named after the same engine — never shared multi-engine helpers), validates each
// against the current ATT&CK index (remapping MITRE-revoked IDs, dropping unknowns), and returns
// the techniques beyond the engine's primary mapping.

import fs from 'node:fs'
import path from 'node:path'

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

function buildDispatchMap(dispatchRs) {
  const idToFn = new Map()
  const start = dispatchRs.indexOf('match canonical {')
  const end = dispatchRs.lastIndexOf('_ => EngineResult::')
  const chunk = dispatchRs.slice(start, end)
  const armStart = /\n\s*"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>/g
  const matches = [...chunk.matchAll(armStart)]
  for (let i = 0; i < matches.length; i += 1) {
    const m = matches[i]
    const ids = [m[1], ...[...m[2].matchAll(/"([^"]+)"/g)].map((a) => a[1])]
    const bodyStart = m.index + m[0].length
    const bodyEnd = i + 1 < matches.length ? matches[i + 1].index : chunk.length
    const body = chunk.slice(bodyStart, bodyEnd)
    const fn = body.match(/crate::([A-Za-z0-9_]+)::([A-Za-z0-9_]+)/)
    if (fn) for (const id of ids) idToFn.set(id, { module: fn[1], fn: fn[2] })
  }
  return idToFn
}

function fnBody(src, fn) {
  const sig = src.search(new RegExp(`fn\\s+${fn}\\b`))
  if (sig === -1) return null
  let i = src.indexOf('{', sig)
  const startBody = i
  let depth = 0
  for (; i < src.length; i += 1) {
    const c = src[i]
    if (c === '{') depth += 1
    else if (c === '}') {
      depth -= 1
      if (depth === 0) break
    }
  }
  return src.slice(startBody, i + 1)
}

/**
 * @returns {{ perEngine: Object<string,string[]>, idToFn: Map }} perEngine maps an engine id to
 *          the sorted list of code-grounded techniques BEYOND its primary registry mapping.
 */
export function codeGroundedExtras(root, idx, registry) {
  const FE = path.join(root, 'fingerprint_engine/src')
  const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
  const dispatchRs = fs.readFileSync(path.join(FE, 'engine_dispatch.rs'), 'utf8')
  const resolveMap = extractResolveMap(engineRs)
  const idToFn = buildDispatchMap(dispatchRs)

  const fileCache = new Map()
  const readModule = (mod) => {
    if (!fileCache.has(mod)) {
      const p = path.join(FE, `${mod}.rs`)
      fileCache.set(mod, fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null)
    }
    return fileCache.get(mod)
  }

  const fnTcodes = new Map()
  function tcodesForFn(mod, fn) {
    const key = `${mod}::${fn}`
    if (fnTcodes.has(key)) return fnTcodes.get(key)
    const out = new Set()
    fnTcodes.set(key, out) // memoize early — guards call cycles
    const src = readModule(mod)
    const body = src && fnBody(src, fn)
    if (body) {
      for (const m of body.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g)) out.add(m[0])
      const base = fn.replace(/^run_/, '').replace(/_result$/, '')
      if (base.length >= 4) {
        for (const call of body.matchAll(/\b([a-z][a-z0-9_]*)\s*\(/g)) {
          const callee = call[1]
          if (callee === fn || !callee.includes(base)) continue
          if (!new RegExp(`fn\\s+${callee}\\b`).test(src)) continue
          for (const t of tcodesForFn(mod, callee)) out.add(t)
        }
      }
    }
    return out
  }

  const normalize = (id) =>
    idx.techniques[id] ? id : idx.revoked_by[id] ? idx.revoked_by[id] : null

  const perEngine = {}
  for (const e of registry) {
    const canon = resolveMap.get(e.id) || e.id
    const fnRef = idToFn.get(canon) || idToFn.get(e.id)
    if (!fnRef) continue
    const valid = new Set()
    for (const t of tcodesForFn(fnRef.module, fnRef.fn)) {
      const n = normalize(t)
      if (n && n !== e.mitre) valid.add(n)
    }
    if (valid.size) perEngine[e.id] = [...valid].sort()
  }
  return { perEngine, idToFn }
}
