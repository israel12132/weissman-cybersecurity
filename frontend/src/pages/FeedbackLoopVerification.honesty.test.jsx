import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FeedbackLoopVerification.jsx'),
  'utf8',
)

describe('FeedbackLoopVerification live-only truth', () => {
  it('does not paint a fake template option when the catalog is unconfirmed', () => {
    expect(src).toMatch(/data-testid="feedback-loop-templates-unavailable"/)
    expect(src).toMatch(/templatesUnavailable/)
    expect(src).toMatch(/templates_unavailable/)
    expect(src).not.toMatch(/<option value=\{DEFAULT_TEMPLATE\}>\{DEFAULT_TEMPLATE\}<\/option>/)
    expect(src).toMatch(/!selectedId \|\| templatesUnavailable/)
    expect(src).toMatch(/useState\(''\)/)
    expect(src).toMatch(/data-testid="feedback-loop-clients-unavailable"/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('mutes leftover leftover-yaml after a failed template-body GET without using shared run error', () => {
    expect(src).toMatch(/const \[yamlUnavailable, setYamlUnavailable\] = useState\(false\)/)
    expect(src).toMatch(/setYamlUnavailable\(false\)/)
    expect(src).toMatch(/setYamlUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="feedback-loop-yaml-unavailable"/)
    expect(src).toMatch(/!!targetUrl\.trim\(\) && !!yaml\.trim\(\) && !yamlUnavailable/)
    expect(src).toMatch(/\.catch\(\(e\) => \{\n        setYamlUnavailable\(true\)\n        setError\(e\?\.message \|\| t\('pages\.feedbackLoopVerification\.load_failed'\)\)/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.feedbackLoopVerification\.run_failed'\)\)/)
    expect(src).not.toMatch(/setYaml\(''\)/)
    expect(src).not.toMatch(/yamlUnavailable \|\| error/)
  })
})
