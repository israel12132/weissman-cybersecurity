import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ThreatHuntingWorkbench.jsx'),
  'utf8',
)

describe('ThreatHuntingWorkbench live-only truth', () => {
  it('does not paint active-hunt zeros when GET /api/soc/hunts fails', () => {
    expect(src).toMatch(/data-testid="threat-hunting-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/campaignsError \? \(\s*<div data-testid="threat-hunting-unavailable"/)
  })
})
