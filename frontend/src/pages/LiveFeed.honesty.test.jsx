import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'LiveFeed.jsx'),
  'utf8',
)

describe('LiveFeed live-only truth', () => {
  it('does not paint an empty ticker when the store is down', () => {
    const catchIdx = src.indexOf('} catch (e) {')
    expect(catchIdx).toBeGreaterThan(-1)
    const finallyIdx = src.indexOf('} finally {', catchIdx)
    const catchBlock = src.slice(catchIdx, finallyIdx === -1 ? undefined : finallyIdx)
    expect(catchBlock).toMatch(/setError/)
    expect(catchBlock).not.toMatch(/setEvents/)
    expect(src).toMatch(/!error &&/)
    expect(src).toMatch(/\{error &&/)
  })
})
