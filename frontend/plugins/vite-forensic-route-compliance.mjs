/**
 * @file Vite AST build-time kill switch — engine routes MUST have forensic evidence enforcement.
 *
 * Scans React Router definitions and cross-references routeEngineId.js + routeEvidence.js.
 * Build fails if any engine hub route lacks:
 *   1. ROUTE_EVIDENCE registry entry (unless explicitly skipped), AND
 *   2. PageShell / ForensicEngineRealityBadge wrapper in the route component AST.
 */
import fs from 'node:fs'
import path from 'node:path'
import { parse } from '@babel/parser'
import _traverse from '@babel/traverse'

const traverse = _traverse.default ?? _traverse

const FORENSIC_WRAPPER_COMPONENTS = new Set([
  'PageShell',
  'MorphingEngineChrome',
  'ForensicPageShell',
  'ForensicEngineRealityBadge',
  'EngineRealityBadge',
  'EngineHubForensicHeader',
])

const FORENSIC_IMPORT_SOURCES = new Set([
  'PageShell',
  'MorphingEngineChrome',
  'ForensicPageShell',
  'ForensicEngineRealityBadge',
  'EngineRealityBadge',
  'EngineHubForensicHeader',
])

/**
 * @param {object} [options]
 * @param {string} [options.root]
 * @returns {import('vite').Plugin}
 */
export function forensicRouteCompliancePlugin(options = {}) {
  const root = options.root ?? process.cwd()
  const srcDir = path.join(root, 'src')

  return {
    name: 'weissman-forensic-route-compliance',
    enforce: 'pre',
    buildStart() {
      const violations = auditForensicRoutes({ root, srcDir })
      if (violations.length > 0) {
        const report = violations.map((v) => `  • ${v}`).join('\n')
        this.error(
          `[forensic-route-compliance] ${violations.length} engine route violation(s) — build aborted:\n${report}\n\nFix: use PageShell (auto-injects ForensicEngineRealityBadge) and register ROUTE_EVIDENCE in src/lib/routeEvidence.js`,
        )
      } else {
        console.log(
          `[forensic-route-compliance] ✓ all engine hub routes pass forensic evidence enforcement`,
        )
      }
    },
  }
}

/**
 * @param {{ root: string, srcDir: string }} ctx
 * @returns {string[]}
 */
export function auditForensicRoutes(ctx) {
  const engineRoutes = loadEngineRouteIds(ctx.srcDir)
  const evidenceRegistry = loadRouteEvidenceRegistry(ctx.srcDir)
  const routeMap = extractRoutesFromMain(ctx.srcDir)
  const violations = []

  for (const [routePath, componentRel] of routeMap.entries()) {
    if (!engineRoutes.has(routePath)) continue

    const componentAbs = path.join(ctx.srcDir, componentRel)
    if (!fs.existsSync(componentAbs)) {
      violations.push(`${routePath}: component file missing (${componentRel})`)
      continue
    }

    if (!evidenceRegistry.skipped.has(routePath) && !evidenceRegistry.exact.has(routePath)) {
      const prefixHit = evidenceRegistry.prefixes.some(
        (p) => routePath === p.replace(/\/$/, '') || routePath.startsWith(p),
      )
      if (!prefixHit) {
        violations.push(
          `${routePath}: missing ROUTE_EVIDENCE entry in routeEvidence.js (issue #9)`,
        )
      }
    }

    const forensic = analyzeComponentForensicWrapper(componentAbs)
    if (!forensic.compliant) {
      violations.push(
        `${routePath}: ${componentRel} lacks forensic wrapper (${forensic.reason})`,
      )
    }
  }

  return violations
}

/**
 * @param {string} srcDir
 */
function loadEngineRouteIds(srcDir) {
  const seedPath = path.join(srcDir, 'lib/engineUiManifests.seed.json')
  const raw = JSON.parse(fs.readFileSync(seedPath, 'utf8'))
  const routes = new Set()
  for (const m of raw.manifests || []) {
    for (const rp of m.route_paths || []) {
      routes.add(rp.startsWith('/') ? rp : `/${rp}`)
    }
  }
  return routes
}

/**
 * @param {string} srcDir
 */
function loadRouteEvidenceRegistry(srcDir) {
  const file = path.join(srcDir, 'lib/routeEvidence.js')
  const src = fs.readFileSync(file, 'utf8')
  const ast = parseModule(src)
  const exact = new Set()
  const skipped = new Set()
  const prefixes = []

  traverse(ast, {
    VariableDeclarator({ node }) {
      if (node.id.type !== 'Identifier') return
      const name = node.id.name
      if (name === 'ROUTE_EVIDENCE' && node.init?.type === 'ObjectExpression') {
        for (const prop of node.init.properties) {
          if (prop.type === 'ObjectProperty' && prop.key.type === 'StringLiteral') {
            exact.add(prop.key.value)
          }
        }
      }
      if (name === 'ROUTE_EVIDENCE_SKIP' && node.init?.type === 'NewExpression') {
        const args = node.init.arguments[0]
        if (args?.type === 'ArrayExpression') {
          for (const el of args.elements) {
            if (el?.type === 'StringLiteral') skipped.add(el.value)
          }
        }
      }
      if (name === 'ROUTE_EVIDENCE_PREFIX' && node.init?.type === 'ArrayExpression') {
        for (const el of node.init.elements) {
          if (el?.type === 'ObjectExpression') {
            const prefixProp = el.properties.find(
              (p) => p.type === 'ObjectProperty' && p.key.name === 'prefix',
            )
            if (prefixProp?.value?.type === 'StringLiteral') {
              prefixes.push(prefixProp.value.value)
            }
          }
        }
      }
    },
  })

  return { exact, skipped, prefixes }
}

/**
 * @param {string} srcDir
 * @returns {Map<string, string>}
 */
function extractRoutesFromMain(srcDir) {
  const routeFile = path.join(srcDir, 'TacticalApp.jsx')
  const chunksFile = path.join(srcDir, 'routing/routeChunks.js')
  const src = fs.readFileSync(routeFile, 'utf8')
  const ast = parseModule(src, true)
  const lazyImports = loadLazyImportsFromRouteChunks(srcDir, chunksFile)
  const routes = new Map()

  traverse(ast, {
    JSXOpeningElement({ node }) {
      if (node.name.type !== 'JSXIdentifier' || node.name.name !== 'Route') return
      let routePath = null
      let elementName = null
      for (const attr of node.attributes) {
        if (attr.type !== 'JSXAttribute') continue
        if (attr.name.name === 'path' && attr.value?.type === 'StringLiteral') {
          routePath = normalizeRoutePath(attr.value.value)
        }
        if (attr.name.name === 'element' && attr.value?.type === 'JSXExpressionContainer') {
          elementName = extractElementComponent(attr.value.expression)
        }
      }
      if (!routePath || !elementName) return
      const componentFile = lazyImports.get(elementName)
      if (componentFile) {
        routes.set(routePath, componentFile)
      }
    },
  })

  return routes
}

/**
 * @param {string} srcDir
 * @param {string} chunksFile
 */
function loadLazyImportsFromRouteChunks(srcDir, chunksFile) {
  const lazyImports = new Map()
  if (!fs.existsSync(chunksFile)) return lazyImports
  const src = fs.readFileSync(chunksFile, 'utf8')
  const ast = parseModule(src, true)
  traverse(ast, {
    CallExpression(path) {
      const node = path.node
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.name === 'React' &&
        node.callee.property.name === 'lazy' &&
        node.arguments[0]?.type === 'ArrowFunctionExpression'
      ) {
        const body = node.arguments[0].body
        const importSpec =
          body.type === 'ImportExpression' && body.source?.type === 'StringLiteral'
            ? body.source.value
            : body.type === 'CallExpression' &&
                body.callee.type === 'Import' &&
                body.arguments[0]?.type === 'StringLiteral'
              ? body.arguments[0].value
              : null
        if (importSpec) {
          const declarator = path.parentPath
          if (declarator?.isVariableDeclarator() && declarator.node.id.type === 'Identifier') {
            lazyImports.set(
              declarator.node.id.name,
              resolveImportPath(srcDir, chunksFile, importSpec),
            )
          }
        }
      }
    },
  })
  return lazyImports
}

/**
 * @param {import('@babel/types').Expression | import('@babel/types').JSXElement} expr
 */
function extractElementComponent(expr) {
  if (expr.type === 'JSXElement') {
    if (expr.openingElement.name.type === 'JSXIdentifier') {
      const name = expr.openingElement.name.name
      const WRAPPER = new Set(['ProtectedRoute', 'CeoProtectedRoute', 'React', 'Suspense'])
      if (!WRAPPER.has(name)) return name
    }
    for (const child of expr.children) {
      if (child.type === 'JSXElement') {
        const inner = extractElementComponent(child)
        if (inner) return inner
      }
      if (child.type === 'JSXExpressionContainer') {
        const inner = extractElementComponent(child.expression)
        if (inner) return inner
      }
    }
    return null
  }
  if (expr.type === 'JSXFragment') {
    for (const child of expr.children) {
      if (child.type === 'JSXElement') {
        const inner = extractElementComponent(child)
        if (inner) return inner
      }
    }
  }
  return null
}

/**
 * @param {string} componentAbs
 */
function analyzeComponentForensicWrapper(componentAbs) {
  const src = fs.readFileSync(componentAbs, 'utf8')

  if (src.includes('@weissman-forensic-page')) {
    return { compliant: true, reason: 'pragma' }
  }

  const ast = parseModule(src, true)
  let importsForensic = false
  let usesForensicJsx = false

  traverse(ast, {
    ImportDeclaration({ node }) {
      for (const spec of node.specifiers) {
        const imported =
          spec.type === 'ImportDefaultSpecifier'
            ? spec.local.name
            : spec.type === 'ImportSpecifier'
              ? spec.imported.name
              : null
        if (imported && FORENSIC_IMPORT_SOURCES.has(imported)) {
          importsForensic = true
        }
      }
      const base = path.basename(node.source.value, path.extname(node.source.value))
      if (FORENSIC_IMPORT_SOURCES.has(base)) {
        importsForensic = true
      }
    },
    JSXOpeningElement({ node }) {
      if (node.name.type === 'JSXIdentifier' && FORENSIC_WRAPPER_COMPONENTS.has(node.name.name)) {
        usesForensicJsx = true
      }
    },
  })

  if (importsForensic && usesForensicJsx) {
    return { compliant: true, reason: 'wrapper' }
  }
  if (importsForensic && src.includes('<PageShell')) {
    return { compliant: true, reason: 'pageshell' }
  }
  return {
    compliant: false,
    reason: 'must import and render PageShell or ForensicEngineRealityBadge',
  }
}

/**
 * @param {string} src
 * @param {boolean} [jsx]
 */
function parseModule(src, jsx = false) {
  return parse(src, {
    sourceType: 'module',
    plugins: jsx ? ['jsx', 'importAttributes'] : ['importAttributes'],
  })
}

/**
 * @param {string} srcDir
 * @param {string} fromFile
 * @param {string} spec
 */
function resolveImportPath(srcDir, fromFile, spec) {
  const base = path.dirname(fromFile)
  let resolved = spec.startsWith('.') ? path.resolve(base, spec) : path.join(srcDir, spec)
  for (const ext of ['.jsx', '.tsx', '.js', '.ts']) {
    if (fs.existsSync(resolved + ext)) return path.relative(srcDir, resolved + ext)
    if (fs.existsSync(path.join(resolved, 'index' + ext))) {
      return path.relative(srcDir, path.join(resolved, 'index' + ext))
    }
  }
  return path.relative(srcDir, resolved + '.jsx')
}

/**
 * @param {string} p
 */
function normalizeRoutePath(p) {
  const trimmed = p.trim()
  if (!trimmed || trimmed === '/') return '/'
  return trimmed.startsWith('/') ? trimmed.replace(/\/$/, '') || '/' : `/${trimmed}`
}

export default forensicRouteCompliancePlugin
