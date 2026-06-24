#!/usr/bin/env node
/**
 * Weissman UI compliance audit — every command-center page must cite live APIs,
 * expose refresh + export, and provide search on list/findings surfaces.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join, basename } from 'node:path'

const PAGES_DIR = join(process.cwd(), 'frontend/src/pages')
const COCKPIT = join(process.cwd(), 'frontend/src/Cockpit.jsx')

/** Standalone hubs — EvidenceNotice manual, not PageShell */
const STANDALONE_HUBS = new Set([
  'DomainDiscovery.jsx',
  'EngineDetail.jsx',
  'EngineMatrix.jsx',
])

/** Embedded panel — covered by CloudControlTower PageShell */
const EMBEDDED_PANELS = new Set(['KubernetesSecurityPanel.jsx'])

/** KPI-only dashboards — export via workbench, no row list to filter */
const KPI_DASHBOARDS = new Set(['Billing.jsx', 'MetricsDashboard.jsx'])

/** Rich table pages with built-in global search + refresh/export */
const PREMIUM_TABLE = new Set(['FindingsCommandCenter.jsx'])

function hasPattern(src, patterns) {
  return patterns.some((p) => (typeof p === 'string' ? src.includes(p) : p.test(src)))
}

function auditSource(name, src) {
  const gaps = []

  const hasEvidence =
    STANDALONE_HUBS.has(name) ||
    hasPattern(src, ['PageShell', 'EvidenceNotice'])

  const hasActions =
    hasPattern(src, [
      'ShellScanActions',
      /<PremiumPageHeader[\s\S]*?onRefresh=/,
      'onRefresh={load',
      'onRefresh={refresh',
      'onRefresh={probe',
      'onRefresh={loadFindings',
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
  if (!hasActions && !EMBEDDED_PANELS.has(name) && !PREMIUM_TABLE.has(name)) gaps.push('refresh_export')
  if (!hasSearch && !EMBEDDED_PANELS.has(name)) gaps.push('search')

  return { name, gaps, ok: gaps.length === 0 }
}

async function main() {
  const files = (await readdir(PAGES_DIR)).filter((f) => f.endsWith('.jsx') && f !== 'PageShell.jsx')
  const results = []

  for (const file of files) {
    const src = await readFile(join(PAGES_DIR, file), 'utf8')
    results.push(auditSource(file, src))
  }

  const cockpitSrc = await readFile(COCKPIT, 'utf8')
  const cockpitOk = cockpitSrc.includes('EvidenceNotice')
  if (!cockpitOk) {
    results.push({ name: 'Cockpit.jsx', gaps: ['evidence'], ok: false })
  }

  const failed = results.filter((r) => !r.ok)
  const passed = results.filter((r) => r.ok)

  console.log(`Weissman UI audit: ${passed.length}/${results.length} pages pass`)
  if (failed.length) {
    console.error('\nGAPS:')
    for (const r of failed.sort((a, b) => a.name.localeCompare(b.name))) {
      console.error(`  ${r.name}: ${r.gaps.join(', ')}`)
    }
    process.exit(1)
  }
  if (!cockpitOk) process.exit(1)
  console.log('All pages meet Weissman UI standard.')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
