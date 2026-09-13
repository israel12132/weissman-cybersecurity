import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ContainmentRulesTab.jsx'),
  'utf8',
)

describe('ContainmentRulesTab live-only truth', () => {
  it('does not paint leftover leftover-rules in the execute select after a failed rules GET', () => {
    expect(src).toMatch(/\{\(!loadError \? rules : \[\]\)\.map\(r => \(/)
    expect(src).toMatch(/if \(loadError\) return/)
    expect(src).toMatch(/data-testid="containment-rules-unavailable"/)
    expect(src).toMatch(/setLoadError\(e\?\.message \|\| t\(`\$\{NS\}\.unavailable`\)\)/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n      setLoadError\(e\?\.message \|\| t\(`\$\{NS\}\.unavailable`\)\)\n      setRules\(\[\]\)/)
  })
})
