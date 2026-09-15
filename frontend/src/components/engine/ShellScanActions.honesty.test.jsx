import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ShellScanActions.jsx'),
  'utf8',
)

describe('ShellScanActions live-only truth', () => {
  it('does not paint leftover leftover-GET Export CSV when onExport is omitted', () => {
    expect(src).toMatch(/\{typeof onExport === 'function' && \(/)
    expect(src).toMatch(/onClick=\{onExport\}/)
    expect(src).toMatch(/exportLabel \|\| t\('weissmanFindings\.export_csv'\)/)
  })
})
