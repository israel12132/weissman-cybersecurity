import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SecurityPosture.jsx'),
  'utf8',
)

describe('SecurityPosture live-only truth', () => {
  it('does not paint leftover leftover-grade chrome after a failed posture GET', () => {
    expect(src).toMatch(/badge=\{error \? t\(`\$\{NS\}\.badge`\) : \(data\?\.grade \?/)
    expect(src).toMatch(/badgeColor=\{gradeColor\(error \? undefined : data\?\.grade\)\}/)
    expect(src).toMatch(/\{!loading && !error && data && \(/)
    expect(src).not.toMatch(/setData\(null\)/)
  })
})
