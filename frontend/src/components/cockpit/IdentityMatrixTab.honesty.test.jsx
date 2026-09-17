import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IdentityMatrixTab.jsx'),
  'utf8',
)

describe('IdentityMatrixTab live-only truth', () => {
  it('does not paint leftover leftover-contexts after a failed identity GET', () => {
    expect(src).toMatch(/\{loadError \? null : \(/)
    expect(src).toMatch(/\{!loadError && contexts\.length >= 2 && \(/)
    expect(src).not.toMatch(/loadError && contexts\.length === 0 \? null/)
    expect(src).toMatch(/setLoadError\(e\?\.message \|\| t\(`\$\{IM\}\.unavailable`\)\)/)
    expect(src).not.toMatch(/setLoadError\(e\?\.message \|\| t\(`\$\{IM\}\.unavailable`\)\)\n {8}setContexts\(\[\]\)/)
    expect(src).not.toMatch(/setLoadError\(t\(`\$\{IM\}\.unavailable`\)\)\n {10}setContexts\(\[\]\)/)
  })
})
