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
})
