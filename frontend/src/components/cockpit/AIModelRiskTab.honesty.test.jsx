import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AIModelRiskTab.jsx'),
  'utf8',
)

describe('AIModelRiskTab live-only truth', () => {
  it('does not paint a blank LLM endpoint row when integrations load fails', () => {
    expect(src).toMatch(/data-testid="ai-model-risk-endpoints-unavailable"/)
    expect(src).toMatch(/endpoints_unavailable/)
    expect(src).toMatch(/setEndpointsUnavailable\(true\)/)
    expect(src).not.toMatch(/if \(e\?\.status\) return/)
  })

  it('does not paint leftover leftover-events after a failed llm-fuzz GET', () => {
    expect(src).toMatch(/data=\{loadError \? \[\] : events\}/)
    expect(src).toMatch(/data-testid="ai-model-risk-unavailable"/)
    expect(src).toMatch(/setLoadError\(e\?\.message \|\| t\(`\$\{NS\}\.unavailable`\)\)/)
    expect(src).not.toMatch(/setEvents\(\[\]\)/)
  })
})
