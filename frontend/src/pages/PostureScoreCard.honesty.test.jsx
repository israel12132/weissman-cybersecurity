import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PostureScoreCard.jsx'),
  'utf8',
)

describe('PostureScoreCard live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV and PDF after a failed posture GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/posture\/score\/\$\{encodeURIComponent\(id\)\}`\)/)
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !data\}/)
    expect(src).toMatch(/\{!error && \(\s*<Button\s*variant="unstyled"\s*type="button"\s*onClick=\{exportPdf\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'load failed'\)/)
  })
})
