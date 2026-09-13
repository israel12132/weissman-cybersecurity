import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FindingsCommandCenter.jsx'),
  'utf8',
)

describe('FindingsCommandCenter live-only truth', () => {
  it('does not paint leftover leftover-last-updated after a failed findings GET', () => {
    expect(src).toMatch(/lastUpdated=\{error \? null : lastUpdated\}/)
    expect(src).toMatch(/count=\{error \? null : totalFiltered\}/)
    expect(src).toMatch(/if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/!error && \(tableData\.length > 0 \|\| loading\)/)
  })
})
