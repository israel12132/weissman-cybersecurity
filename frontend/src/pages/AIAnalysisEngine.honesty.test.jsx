import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AIAnalysisEngine.jsx'),
  'utf8',
)

describe('AIAnalysisEngine live-only truth', () => {
  it('does not paint KPI zeros when findings load is unconfirmed', () => {
    expect(src).toMatch(/data-testid="ai-analysis-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/const findingsList = Array\.isArray\(fd\) \? fd : Array\.isArray\(fd\?\.findings\) \? fd\.findings : null/)
    expect(src).toMatch(/if \(findingsList\) \{/)
    expect(src).toMatch(/!loading && !error && filtered\.length === 0/)
    expect(src).not.toMatch(/if \(fd\) \{\s*findingsOk = true/)
  })
})
