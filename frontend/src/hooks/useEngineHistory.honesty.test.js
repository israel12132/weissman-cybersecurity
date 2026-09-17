import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'useEngineHistory.js'),
  'utf8',
)
const pageSrc = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'useWeissmanEnginePage.js'),
  'utf8',
)

describe('useEngineHistory live-only truth', () => {
  it('does not treat a failed history fetch as confirmed never-run', () => {
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/return \{ unavailable: true \}/)
    expect(src).toMatch(/Array\.isArray\(d\.jobs\)/)
    expect(src).not.toMatch(/catch \{\s*return null\s*\}/)
  })
})

describe('applyHistoryFindings live-only truth', () => {
  it('does not apply unavailable history as empty findings', () => {
    expect(pageSrc).toMatch(/if \(!run \|\| run\.unavailable\) return false/)
  })
})
