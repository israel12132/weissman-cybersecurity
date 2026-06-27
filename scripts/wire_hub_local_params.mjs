#!/usr/bin/env node
/**
 * Wire hub pages with local params or buildBody():
 * - useSyncHubScanParams → postScan merges full param state
 * - hideHubParams on PageShell (avoid duplicate compact panel)
 */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const pagesDir = path.join(root, 'frontend/src/pages')

const SYNC_IMPORT = "import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'"
const PREFILL_IMPORT = "import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'"

function detectEngineVar(text) {
  const m = text.match(/const\s+(ENGINE_ID|ENGINE|FLAGSHIP_ID|MOBILE_ENGINE)\s*=/)
  return m?.[1] || null
}

function ensureImport(text, line) {
  if (text.includes(line)) return text
  const hookImport = text.match(/^import .+ from '\.\.\/hooks\/useCommandCenterScan'/m)
  if (hookImport) return text.replace(hookImport[0], `${hookImport[0]}\n${line}`)
  const firstImport = text.match(/^import .+$/m)
  if (firstImport) return text.replace(firstImport[0], `${firstImport[0]}\n${line}`)
  return text
}

function ensureUseMemoImport(text) {
  if (/import React, \{[^}]*useMemo/.test(text)) return text
  if (/import \{[^}]*useMemo/.test(text)) return text
  return text.replace(
    /import React, \{([^}]+)\}/,
    (m, inner) => `import React, {${inner.includes('useMemo') ? inner : `${inner}, useMemo`}}`,
  )
}

function ensureHideHubParams(text) {
  if (!text.includes('<PageShell') || text.includes('hideHubParams')) return text
  if (text.includes('<PageShell\n')) {
    return text.replace('<PageShell\n', '<PageShell\n      hideHubParams\n')
  }
  return text.replace('<PageShell ', '<PageShell hideHubParams ')
}

function wireDefaultParams(text) {
  const engineVar = detectEngineVar(text)
  if (!engineVar) return { text, changed: false }
  if (text.includes('const buildBody = useCallback')) return { text, changed: false }

  const stateRe = /const \[params, setParams\] = useState\((DEFAULT_PARAMS|defaultParams)\)/
  const stateMatch = text.match(stateRe)
  if (!stateMatch) return { text, changed: false }

  const insert = `  useSyncHubScanParams(${engineVar}, params)\n  useIntegrationsPrefill(${engineVar}, clientId, setParams)`
  if (text.includes(`useSyncHubScanParams(${engineVar}, params)`)) {
    if (!text.includes('useIntegrationsPrefill')) {
      text = text.replace(stateRe, `${stateMatch[0]}\n  useIntegrationsPrefill(${engineVar}, clientId, setParams)`)
      text = ensureImport(text, PREFILL_IMPORT)
      return { text, changed: true }
    }
    return { text, changed: false }
  }

  text = ensureImport(text, SYNC_IMPORT)
  text = ensureImport(text, PREFILL_IMPORT)
  text = text.replace(stateRe, `${stateMatch[0]}\n${insert}`)
  return { text, changed: true }
}

function wireBuildBody(text) {
  const engineVar = detectEngineVar(text)
  if (!engineVar || !text.includes('const buildBody = useCallback')) return { text, changed: false }

  const marker = `useSyncHubScanParams(${engineVar}, hubScanParams)`
  if (text.includes(marker)) return { text, changed: false }

  const buildBodyRe = /const buildBody = useCallback\(\(\) => \{[\s\S]*?\n  \}, \[[^\]]+\]\)/
  const m = text.match(buildBodyRe)
  if (!m) return { text, changed: false }

  text = ensureImport(text, SYNC_IMPORT)
  text = ensureUseMemoImport(text)

  const snippet = `${m[0]}

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  ${marker}`

  text = text.replace(buildBodyRe, snippet)
  return { text, changed: true }
}

function wireFile(filePath) {
  let text = fs.readFileSync(filePath, 'utf8')
  const rel = path.relative(pagesDir, filePath)

  const hasLocal =
    text.includes('const DEFAULT_PARAMS')
    || text.includes('const defaultParams')
    || text.includes('const buildBody = useCallback')
    || text.includes('function buildScanBody')

  if (!hasLocal) return false

  const before = text
  let changed = false

  if (!text.includes('useSyncHubScanParams')) {
    const r1 = wireDefaultParams(text)
    text = r1.text
    changed = changed || r1.changed

    const r2 = wireBuildBody(text)
    text = r2.text
    changed = changed || r2.changed
  } else if (text.includes('useState(defaultParams)') && !text.includes('useIntegrationsPrefill')) {
    const r = wireDefaultParams(text)
    text = r.text
    changed = changed || r.changed
  }

  const afterHide = ensureHideHubParams(text)
  if (afterHide !== text) {
    text = afterHide
    changed = true
  }

  if (!detectEngineVar(text) && changed) {
    console.warn(`  warn ${rel}: wired but no ENGINE const found`)
  }

  if (text !== before) {
    fs.writeFileSync(filePath, text)
    console.log(`  wired ${rel}`)
    return true
  }
  return false
}

const files = fs.readdirSync(pagesDir).filter((f) => f.endsWith('.jsx'))
let count = 0
for (const f of files) {
  if (wireFile(path.join(pagesDir, f))) count += 1
}

console.log(`wire_hub_local_params: ${count} file(s) updated`)
