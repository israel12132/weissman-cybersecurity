import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'GlobalEdgeSwarmMap.jsx'),
  'utf8',
)

describe('GlobalEdgeSwarmMap live-only truth', () => {
  it('does not paint leftover leftover-swarm nodes after a failed nodes GET', () => {
    expect(src).toMatch(/\{manifest && !error && \(/)
    expect(src).toMatch(/\{\!error && nodes\.map\(\(n\) => \{/)
    expect(src).toMatch(/\{\!error && nodes\.length > 0 && \(/)
    expect(src).toMatch(/data-testid="edge-swarm-unavailable"/)
    expect(src).toMatch(/\} catch \(e\) \{\n      setError\(e\?\.message \|\| t\(`\$\{NS\}\.unavailable`\)\)/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n      setNodes/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n      setManifest/)
  })
})
