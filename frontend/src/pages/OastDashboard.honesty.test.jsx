import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'OastDashboard.jsx'),
  'utf8',
)

const poll = src.slice(src.indexOf('const handlePollToken'), src.indexOf('const labelForProbe'))
const mint = src.slice(src.indexOf('const handleMintToken'), src.indexOf('const handlePollToken'))

describe('OastDashboard live-only truth', () => {
  it('mutes leftover leftover-verify overlay after a failed GET /api/oast/verify/:token', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/oast\/verify\/\$\{token\}`\)/)
    expect(src).toMatch(/\{ \.\.\.tok, \.\.\.data, pollUnavailable: false \}/)
    expect(src).toMatch(/\{ \.\.\.tok, pollUnavailable: true \}/)
    expect(src).toMatch(/data-testid="oast-verify-unavailable"/)
    expect(src).toMatch(/tok\.pollUnavailable \? \(/)
    expect(src).toMatch(/!tok\.pollUnavailable && tok\.first_hit_at && \(/)
    expect(src).toMatch(/pages\.oastDashboard\.verify_unavailable/)
  })

  it('keeps leftover leftover-verify fields in mintedTokens state and does not catch-clear the token list', () => {
    expect(poll).not.toMatch(/setMintedTokens\(\[\]\)/)
    expect(poll).not.toMatch(/oob_confirmed:\s*false/)
    expect(poll).not.toMatch(/first_hit_at:\s*null/)
    expect(poll).not.toMatch(/hit_count:\s*0/)
    expect(src).toMatch(/\{tok\.token\}/)
    expect(src).toMatch(/tok\.callback_domain \?\? '—'/)
    expect(src).toMatch(/onClick=\{\(\) => handlePollToken\(tok\.token\)\}/)
  })

  it('keeps pollUnavailable GET-only — mint POST toast does not mute leftover leftover-verify', () => {
    expect(mint).not.toMatch(/pollUnavailable/)
    expect(mint).toMatch(/pages\.oastDashboard\.mint_failed/)
    expect(src).not.toMatch(/!toast && tok\.oob_confirmed/)
    expect(src).not.toMatch(/toast && tok\.oob_confirmed/)
  })
})
