import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DarkWebMonitor.jsx'),
  'utf8',
)

describe('DarkWebMonitor live-only truth', () => {
  it('does not paint zero dark-web hits when findings fetch fails', () => {
    expect(src).toMatch(/data-testid="dark-web-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })

  it('does not paint leftover leftover-last-updated after a failed findings GET', () => {
    expect(src).toMatch(/\{lastRefresh && !error && \(/)
  })

  it('does not paint leftover leftover-finding counts after a failed findings GET', () => {
    expect(src).toMatch(/\{!error && \(\n                <span className="text-\[var\(--text-muted\)\] font-mono text-xs">\(\{filtered\.length\}\)<\/span>/)
    expect(src).toMatch(/if \(error \|\| !filtered\.length\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| filtered\.length === 0\}/)
  })

  it('does not paint leftover leftover-source options after a failed findings GET', () => {
    expect(src).toMatch(/\{sources\.length > 1 && !error && \(/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=5000'\)/)
    expect(src).toMatch(/if \(error \|\| !filtered\.length\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| filtered\.length === 0\}/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })
})
