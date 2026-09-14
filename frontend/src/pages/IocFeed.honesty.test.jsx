import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IocFeed.jsx'),
  'utf8',
)

describe('IocFeed live-only truth', () => {
  it('does not dump leftover leftover-IOCs CSV after a failed IOCs GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setIocs\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed IOCs GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/soc\/iocs'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="ioc-feed-unavailable"/)
    expect(src).not.toMatch(/setIocs\(\[\]\)/)
  })
})
