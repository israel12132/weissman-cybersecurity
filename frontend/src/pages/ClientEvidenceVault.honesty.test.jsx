import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientEvidenceVault.jsx'),
  'utf8',
)

describe('ClientEvidenceVault live-only truth', () => {
  it('does not window.open a download that cannot surface 503', () => {
    expect(src).not.toMatch(/window\.open/)
    expect(src).toMatch(/raw:\s*true/)
    expect(src).toMatch(/\/api\/evidence\/\$\{item\.id\}\/download/)
    expect(src).toMatch(/download_failed/)
  })
})
