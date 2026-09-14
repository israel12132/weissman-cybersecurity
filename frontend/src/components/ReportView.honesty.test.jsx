import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ReportView.jsx'),
  'utf8',
)

describe('ReportView live-only truth', () => {
  it('mutes leftover leftover-GET PDF export and crypto-proof chrome after a failed report GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/clients'/)
    expect(src).toMatch(/apiFetch\('\/api\/findings'/)
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/report\/crypto-proof`/)
    expect(src).toMatch(/actions=\{\!error \? \(/)
    expect(src).toMatch(/api\/clients\/\$\{clientId\}\/report\/pdf/)
    expect(src).toMatch(/!error && \(\s*<section className="rounded-xl border border-cyan-500\/40/)
    expect(src).toMatch(/components\.reportView\.crypto_sealed_body/)
    expect(src).toMatch(/data-testid="report-unavailable"/)
  })
})
