import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ItdrCommandCenter.jsx'),
  'utf8',
)

describe('ItdrCommandCenter live-only truth', () => {
  it('does not dump leftover leftover-events CSV after a failed ITDR GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setEvents\(\[\]\)/)
  })
})
