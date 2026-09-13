import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { invalidateEngineHistorySummary } from './engineHistorySummary.js'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'engineHistorySummary.js'),
  'utf8',
)

describe('engineHistorySummary', () => {
  it('invalidate noop', () => expect(() => invalidateEngineHistorySummary()).not.toThrow())

  it('does not cache a fake empty history map on fetch failure', () => {
    expect(src).toMatch(/cachedSummary \?\? null/)
    expect(src).not.toMatch(/cachedSummary = \{\}/)
    expect(src).not.toMatch(/return \{\}/)
  })
})
