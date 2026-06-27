#!/usr/bin/env node
/**
 * Ensures rich hub pages sync local params to EngineHubContext.
 */
import fs from 'node:fs'
import path from 'node:path'

const pagesDir = path.join(path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'), 'frontend/src/pages')
const violations = []

function needsSync(text) {
  return text.includes('const DEFAULT_PARAMS')
    || text.includes('const defaultParams')
    || text.includes('const buildBody = useCallback')
    || text.includes('function buildScanBody')
}

for (const file of fs.readdirSync(pagesDir).filter((f) => f.endsWith('.jsx'))) {
  const text = fs.readFileSync(path.join(pagesDir, file), 'utf8')
  if (!text.includes('useCommandCenterScan') || !text.includes('postScan')) continue
  if (!needsSync(text)) continue

  if (!text.includes('useSyncHubScanParams') && !text.includes('useHubBodySync')) {
    violations.push(`${file}: missing useSyncHubScanParams or useHubBodySync`)
  }
  if (text.includes('<PageShell') && !text.includes('hideHubParams')) {
    violations.push(`${file}: PageShell missing hideHubParams`)
  }
}

// Child panel embedded in Cloud Control Tower
const k8s = path.join(pagesDir, 'KubernetesSecurityPanel.jsx')
if (fs.existsSync(k8s)) {
  const text = fs.readFileSync(k8s, 'utf8')
  if (!text.includes('useSyncHubScanParams')) violations.push('KubernetesSecurityPanel.jsx: missing useSyncHubScanParams')
}

if (violations.length) {
  console.error('verify_hub_local_params: FAIL')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log('verify_hub_local_params: OK')
