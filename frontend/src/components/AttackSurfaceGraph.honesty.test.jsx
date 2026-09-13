import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AttackSurfaceGraph.jsx'),
  'utf8',
)

describe('AttackSurfaceGraph live-only truth', () => {
  it('does not paint leftover leftover-graph after a failed attack-surface-graph GET', () => {
    expect(src).toMatch(/subtitle=\{error \|\| graph\.run_id == null \? undefined : t\(/)
    expect(src).toMatch(/\{\!error && graph\.message && !graph\.nodes\?\.length && \(/)
    expect(src).toMatch(/\{\/\* Leftover graph stays in React state; mute paint on failed attack-surface-graph GET \*\/\}\n      \{\!error && \(/)
    expect(src).toMatch(/data-testid="asm-graph-unavailable"/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).not.toMatch(/setGraph\(\{ nodes: \[\], edges: \[\], run_id: null/)
  })
})
