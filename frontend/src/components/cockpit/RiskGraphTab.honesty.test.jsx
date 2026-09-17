import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RiskGraphTab.jsx'),
  'utf8',
)

describe('RiskGraphTab live-only truth', () => {
  it('does not paint leftover leftover-graph after a failed risk-graph GET', () => {
    expect(src).toMatch(/\) : error \? \(\n {10}<div className="flex items-center justify-center h-full text-red-300\/80 text-sm px-6 text-center">/)
    expect(src).not.toMatch(/error && nodes\.length === 0/)
    expect(src).toMatch(/data-testid="risk-graph-unavailable"/)
    expect(src).toMatch(/setError\(err\?\.message \|\| t\('components\.cockpitTabs\.riskGraph\.unavailable'\)\)/)
    expect(src).not.toMatch(/\} catch \(err\) \{\n {6}if \(err\?\.name === 'AbortError' \|\| signal\?\.aborted\) return\n {6}setError\(err\?\.message \|\| t\('components\.cockpitTabs\.riskGraph\.unavailable'\)\)\n {6}setNodes\(\[\]\)/)
  })
})
