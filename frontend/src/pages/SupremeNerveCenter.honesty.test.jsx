import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SupremeNerveCenter.jsx'),
  'utf8',
)

describe('SupremeNerveCenter live-only truth', () => {
  it('does not paint running-now zeros without a confirmed snapshot', () => {
    expect(src).toMatch(/data-testid="supreme-nerve-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/section === 'overview' && !error && snap &&/)
    expect(src).not.toMatch(/value=\{summary\.engines_running \?\? 0\}/)
  })

  it('does not dump leftover leftover-nerve JSON after a failed nerve-center GET', () => {
    expect(src).toMatch(/const handleExport = useCallback\(async \(\) => \{\n    if \(error \|\| !snap\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !snap\}/)
    expect(src).toMatch(/stuckEngines\.length > 0 && !error/)
    expect(src).toMatch(/lastRefresh && !error \? lastRefresh\.toLocaleTimeString/)
    expect(src).not.toMatch(/setSnap\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed nerve-center GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/ceo\/supreme\/nerve-center'\)/)
    expect(src).toMatch(/const handleExport = useCallback\(async \(\) => \{\n    if \(error \|\| !snap\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExport\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !snap\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="supreme-nerve-unavailable"/)
    expect(src).not.toMatch(/setSnap\(null\)/)
  })
})
