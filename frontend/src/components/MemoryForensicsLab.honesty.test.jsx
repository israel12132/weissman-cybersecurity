import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'MemoryForensicsLab.jsx'),
  'utf8',
)

describe('MemoryForensicsLab live-only truth', () => {
  it('mutes leftover leftover-selected hex and weaponization after a failed poe-findings GET', () => {
    expect(src).toMatch(/\{selected && !findingsError && \(\n              <div className="mt-4 p-3 rounded-lg bg-cyan-500\/10/)
    expect(src).toMatch(/\{selected && !findingsError \? \(/)
    expect(src).toMatch(/\{selected && !findingsError && \(\n          <div className="rounded-xl bg-\[var\(--bg-1\)\]\/80 border border-\[var\(--border-default\)\]\/60 p-6">/)
    expect(src).toMatch(/setFindingsError\(e\?\.message \|\| t\(`\$\{NS\}\.fetch_failed`\)\)/)
    expect(src).not.toMatch(/setFindingsError\(e\?\.message \|\| t\(`\$\{NS\}\.fetch_failed`\)\)\n        setFindings\(\[\]\)/)
    expect(src).not.toMatch(/setFindingsError\(e\?\.message \|\| t\(`\$\{NS\}\.fetch_failed`\)\)\n        setSelected\(null\)/)
  })
})
