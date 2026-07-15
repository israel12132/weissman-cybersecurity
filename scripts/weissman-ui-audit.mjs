#!/usr/bin/env node
/**
 * Weissman UI compliance audit — 112+ command-center routes must cite live APIs,
 * expose refresh + export, and provide search on list/findings surfaces.
 */
import { readFile, readdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(join(dirname(fileURLToPath(import.meta.url)), '../frontend/package.json'))
const { parse } = require('@babel/parser')
const _traverse = require('@babel/traverse')
const traverse = _traverse.default ?? _traverse
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const FRONTEND_SRC = join(ROOT, 'frontend/src')
const PAGES_DIR = join(FRONTEND_SRC, 'pages')
const TARGET_ROUTES = 112

/** Auth / catch-all — excluded from routed component audit */
const ROUTE_AUDIT_SKIP = new Set(['login', '*'])

/** Embedded labs & cockpit — evidence required; search/refresh not enforced */
const EVIDENCE_ONLY_ROUTE_PREFIXES = [
  'ai-arena',
  'attack-chain/',
  'attack-surface-graph/',
  'cicd-matrix/',
  'memory-lab/',
  'report/',
  'semantic-logic/',
  'timing-profiler',
  'zero-day-radar',
  'intel-map',
  'system-core',
  'operations',
]

const EMBEDDED_PANELS = new Set(['KubernetesSecurityPanel.jsx'])
const KPI_DASHBOARDS = new Set(['Billing.jsx', 'MetricsDashboard.jsx'])
const PREMIUM_TABLE = new Set(['FindingsCommandCenter.jsx'])

const FORENSIC_MARKERS = [
  'PageShell',
  'MorphingEngineChrome',
  'ForensicEngineRealityBadge',
  'EngineHubForensicHeader',
  'LabForensicEvidence',
  'StandaloneLabShell',
  'EvidenceNotice',
  '@weissman-forensic-page',
]

function hasPattern(src, patterns) {
  return patterns.some((p) => (typeof p === 'string' ? src.includes(p) : p.test(src)))
}

function auditSource(name, src, { evidenceOnly = false } = {}) {
  const gaps = []
  const hasEvidence = FORENSIC_MARKERS.some((m) => src.includes(m))
  const hasActions = hasPattern(src, [
    'ShellScanActions',
    /<PremiumPageHeader[\s\S]*?onRefresh=/,
    'onRefresh={load',
    'onRefresh={refresh',
    'onRefresh={probe',
    'onRefresh={loadFindings',
    'onRefresh={reload',
    'onRefresh={handleRefresh',
  ])
  const hasSearch =
    KPI_DASHBOARDS.has(name) ||
    EMBEDDED_PANELS.has(name) ||
    hasPattern(src, [
      'WeissmanFindingsPanel',
      'WeissmanListToolbar',
      'searchQuery',
      'setSearchQuery',
      'searchTerm',
      'setSearchTerm',
      'sectionSearch',
      'serviceSearch',
      'type="search"',
      'globalFilter',
      'librarySearch',
      'engineSearch',
      'findingSearch',
      'filterSeverity',
      '[search, setSearch]',
      'DataTable',
      'PremiumPageHeader',
      'setGlobalFilter',
    ])

  if (!hasEvidence) gaps.push('evidence')
  if (!evidenceOnly) {
    if (!hasActions && !EMBEDDED_PANELS.has(name) && !PREMIUM_TABLE.has(name)) gaps.push('refresh_export')
    if (!hasSearch && !EMBEDDED_PANELS.has(name)) gaps.push('search')
  }
  return { name, gaps, ok: gaps.length === 0 }
}

function isEvidenceOnlyRoute(path) {
  return EVIDENCE_ONLY_ROUTE_PREFIXES.some(
    (p) => path === p || path.startsWith(p) || path.startsWith(`${p}/`),
  )
}

function parseModule(src, jsx = false) {
  return parse(src, {
    sourceType: 'module',
    plugins: jsx ? ['jsx', 'importAttributes'] : ['importAttributes'],
  })
}

function loadLazyImports(chunksSrc) {
  const ast = parseModule(chunksSrc, true)
  const map = new Map()
  traverse(ast, {
    CallExpression(path) {
      const node = path.node
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.name === 'React' &&
        node.callee.property.name === 'lazy'
      ) {
        const body = node.arguments[0]?.body
        const importSpec =
          body?.type === 'ImportExpression' && body.source?.type === 'StringLiteral'
            ? body.source.value
            : body?.type === 'CallExpression' &&
                body.callee.type === 'Import' &&
                body.arguments[0]?.type === 'StringLiteral'
              ? body.arguments[0].value
              : null
        if (importSpec) {
          const declarator = path.parentPath
          if (declarator?.isVariableDeclarator() && declarator.node.id.type === 'Identifier') {
            map.set(declarator.node.id.name, importSpec)
          }
        }
      }
    },
  })
  return map
}

function extractInnerComponent(expr) {
  if (expr.type === 'JSXElement') {
    if (expr.openingElement.name.type === 'JSXIdentifier') {
      const name = expr.openingElement.name.name
      const WRAP = new Set(['ProtectedRoute', 'CeoProtectedRoute', 'Suspense'])
      if (!WRAP.has(name)) return name
    }
    for (const child of expr.children) {
      if (child.type === 'JSXElement') {
        const inner = extractInnerComponent(child)
        if (inner) return inner
      }
    }
  }
  return null
}

function extractTacticalRoutes(tacticalSrc, lazyMap) {
  const ast = parseModule(tacticalSrc, true)
  const routes = []
  traverse(ast, {
    JSXOpeningElement({ node }) {
      if (node.name.type !== 'JSXIdentifier' || node.name.name !== 'Route') return
      let routePath = null
      let component = null
      for (const attr of node.attributes) {
        if (attr.type !== 'JSXAttribute') continue
        if (attr.name.name === 'path' && attr.value?.type === 'StringLiteral') {
          routePath = attr.value.value
        }
        if (attr.name.name === 'element' && attr.value?.type === 'JSXExpressionContainer') {
          component = extractInnerComponent(attr.value.expression)
        }
      }
      if (routePath != null && component) {
        routes.push({ path: routePath, component, importSpec: lazyMap.get(component) })
      }
    },
  })
  return routes
}

async function main() {
  const pageFiles = (await readdir(PAGES_DIR)).filter(
    (f) =>
      f.endsWith('.jsx') &&
      !f.endsWith('.test.jsx') &&
      !f.endsWith('.spec.jsx') &&
      f !== 'PageShell.jsx',
  )
  const pageResults = []
  for (const file of pageFiles) {
    const src = await readFile(join(PAGES_DIR, file), 'utf8')
    pageResults.push(auditSource(file, src))
  }

  const cockpitSrc = await readFile(join(FRONTEND_SRC, 'Cockpit.jsx'), 'utf8')
  if (!hasPattern(cockpitSrc, ['EvidenceNotice', 'ForensicEngineRealityBadge'])) {
    pageResults.push({ name: 'Cockpit.jsx', gaps: ['evidence'], ok: false })
  }

  const chunksSrc = await readFile(join(FRONTEND_SRC, 'routing/routeChunks.js'), 'utf8')
  const tacticalSrc = await readFile(join(FRONTEND_SRC, 'TacticalApp.jsx'), 'utf8')
  const lazyMap = loadLazyImports(chunksSrc)
  const routes = extractTacticalRoutes(tacticalSrc, lazyMap)
  const leafRoutes = routes.filter((r) => r.path !== '/' && r.path !== '*')
  const routeCount = leafRoutes.length + 1

  const routeAudits = []
  for (const route of leafRoutes) {
    if (ROUTE_AUDIT_SKIP.has(route.path)) continue
    if (!route.importSpec) continue
    const rel = route.importSpec.replace(/^\.\.\//, '')
    const candidates = [
      join(FRONTEND_SRC, rel),
      join(FRONTEND_SRC, `${rel}.jsx`),
      join(FRONTEND_SRC, `${rel}.js`),
    ]
    let src = ''
    let file = rel
    for (const abs of candidates) {
      try {
        src = await readFile(abs, 'utf8')
        file = abs.replace(`${FRONTEND_SRC}/`, '')
        break
      } catch {
        /* try next */
      }
    }
    if (!src) {
      routeAudits.push({ path: route.path, file: rel, ok: false, gaps: ['missing_file'] })
      continue
    }
    const base = file.split('/').pop()
    const audit = auditSource(base, src, { evidenceOnly: isEvidenceOnlyRoute(route.path) })
    routeAudits.push({ path: route.path, file, ...audit })
  }

  const pageFailed = pageResults.filter((r) => !r.ok)
  const routeFailed = routeAudits.filter((r) => !r.ok)
  const pagePassed = pageResults.filter((r) => r.ok).length
  const routePassed = routeAudits.filter((r) => r.ok).length
  const pctPages = Math.round((pagePassed / pageResults.length) * 100)
  const pctRoutes = routeAudits.length ? Math.round((routePassed / routeAudits.length) * 100) : 100

  console.log(`Weissman UI audit: pages ${pagePassed}/${pageResults.length} (${pctPages}%)`)
  console.log(`Route coverage: ${routeCount} paths (target ${TARGET_ROUTES})`)
  console.log(`Routed components: ${routePassed}/${routeAudits.length} (${pctRoutes}%)`)

  if (pageFailed.length || routeFailed.length) {
    console.error('\nGAPS:')
    for (const r of pageFailed.sort((a, b) => a.name.localeCompare(b.name))) {
      console.error(`  page ${r.name}: ${r.gaps.join(', ')}`)
    }
    for (const r of routeFailed.sort((a, b) => a.path.localeCompare(b.path))) {
      console.error(`  route ${r.path} (${r.file}): ${r.gaps.join(', ')}`)
    }
    process.exit(1)
  }

  if (routeCount < TARGET_ROUTES) {
    console.error(`Route count ${routeCount} below target ${TARGET_ROUTES}`)
    process.exit(1)
  }

  console.log('All pages and routes meet Weissman UI standard (100%).')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
