import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CeoVaccineVault.jsx'),
  'utf8',
)

describe('CeoVaccineVault live-only truth', () => {
  it('mutes leftover leftover-selected vault row after a failed vault GET', () => {
    expect(src).toMatch(/\{selected && !err && \(/)
    expect(src).toMatch(/setErr\(e\.message \|\| t\('components\.ceo\.vaccineVault\.loadFailed'\)\)/)
    expect(src).not.toMatch(/setSelected\(null\)/)
  })
})
