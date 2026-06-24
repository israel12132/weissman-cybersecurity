#!/usr/bin/env node
/**
 * Extract per-route intelligence from React source (APIs, engines, descriptions).
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, basename } from 'node:path'

const root = process.cwd()

export function buildComponentPathMap() {
  const main = readFileSync(join(root, 'frontend/src/main.jsx'), 'utf8')
  const map = {}
  for (const m of main.matchAll(
    /const\s+(\w+)\s*=\s*React\.lazy\(\(\)\s*=>\s*import\(['"](\.\/[^'"]+)['"]\)/g,
  )) {
    const name = m[1]
    let rel = m[2].replace(/^\.\//, '')
    if (!rel.endsWith('.jsx')) rel += '.jsx'
    map[name] = join(root, 'frontend/src', rel)
  }
  map.Login = join(root, 'frontend/src/components/cockpit/Login.jsx')
  map.Cockpit = join(root, 'frontend/src/Cockpit.jsx')
  map.App = join(root, 'frontend/src/App.jsx')
  map.NotFound = join(root, 'frontend/src/components/ui/NotFound.jsx')
  return map
}

export function buildRouteComponentMap() {
  const main = readFileSync(join(root, 'frontend/src/main.jsx'), 'utf8')
  const routes = {}
  for (const m of main.matchAll(/<Route\s+path="([^"]+)"\s+element=\{<(\w+)/g)) {
    routes[m[1]] = m[2]
  }
  for (const m of main.matchAll(
    /<Route\s+path="([^"]+)"[\s\S]*?element=\{\s*<(\w+)/g,
  )) {
    if (!routes[m[1]]) routes[m[1]] = m[2]
  }
  return routes
}

export function extractFileIntel(filePath) {
  if (!filePath || !existsSync(filePath)) return { apis: [], engines: [], descriptions: [] }
  const src = readFileSync(filePath, 'utf8')
  const apis = new Set()
  for (const m of src.matchAll(/apiFetch\(\s*[`'"](\/api\/[^'`"]+)/g)) {
    apis.add(m[1].replace(/\$\{[^}]+\}/g, ':param'))
  }
  for (const m of src.matchAll(/fetch\(\s*[`'"](\/api\/[^'`"]+)/g)) {
    apis.add(m[1].replace(/\$\{[^}]+\}/g, ':param'))
  }

  const engines = new Set()
  for (const m of src.matchAll(/engine:\s*['"]([a-z0-9_]+)['"]/g)) engines.add(m[1])
  for (const m of src.matchAll(/ENGINE_ID\s*=\s*['"]([a-z0-9_]+)['"]/g)) engines.add(m[1])
  for (const m of src.matchAll(/['"]([a-z0-9_]+)['"]\s*,\s*\/\/\s*engine/gi)) engines.add(m[1])
  for (const block of src.matchAll(/ENGINE(?:S)?_IDS?\s*=\s*\[([\s\S]*?)\]/g)) {
    for (const id of block[1].matchAll(/['"]([a-z0-9_]+)['"]/g)) engines.add(id[1])
  }
  for (const block of src.matchAll(/ENGINE_DESCRIPTIONS\s*=\s*\{([\s\S]*?)\n\}/g)) {
    for (const id of block[1].matchAll(/^\s*([a-z0-9_]+):/gm)) engines.add(id[1])
  }
  for (const block of src.matchAll(/CLOUD_TABS\s*=\s*\[([\s\S]*?)\]/g)) {
    for (const id of block[1].matchAll(/engine:\s*['"]([a-z0-9_]+)['"]/g)) engines.add(id[1])
  }

  const descriptions = []
  for (const block of src.matchAll(/ENGINE_DESCRIPTIONS\s*=\s*\{([\s\S]*?)\n\}/g)) {
    for (const m of block[1].matchAll(/([a-z0-9_]+):\s*['"]([^'"]+)['"]/g)) {
      descriptions.push({ id: m[1], text: m[2] })
    }
  }

  return {
    apis: [...apis].sort(),
    engines: [...engines].sort(),
    descriptions,
    file: basename(filePath),
  }
}

export function buildRouteIntelMap() {
  const compPaths = buildComponentPathMap()
  const routeComps = buildRouteComponentMap()
  const intel = {}
  for (const [route, comp] of Object.entries(routeComps)) {
    intel[route] = { ...extractFileIntel(compPaths[comp]), component: comp }
  }
  intel['/'] = extractFileIntel(compPaths.Cockpit)
  intel.login = extractFileIntel(compPaths.Login)
  return intel
}

export function parseHttpApiRoutes() {
  const serve = readFileSync(join(root, 'fingerprint_engine/src/http/serve.rs'), 'utf8')
  const routes = []
  for (const m of serve.matchAll(/\.route\(\s*"([^"]+)",\s*(get|post|put|delete|patch)/g)) {
    routes.push({ path: m[1], method: m[2].toUpperCase() })
  }
  return routes.sort((a, b) => a.path.localeCompare(b.path))
}

export function groupApiRoutes(routes) {
  const groups = {}
  for (const r of routes) {
    const parts = r.path.split('/').filter(Boolean)
    const key = parts[1] || 'root'
    ;(groups[key] ||= []).push(r)
  }
  return groups
}
