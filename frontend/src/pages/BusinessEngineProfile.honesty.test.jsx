import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'BusinessEngineProfile.jsx'),
  'utf8',
)

describe('BusinessEngineProfile live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="business-engine-profile-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/clients load failed — leave list unchanged/)
  })

  it('does not treat a failed integrations fetch as unconfigured scan prefill', () => {
    expect(src).toMatch(/data-testid="business-engine-profile-integrations-unavailable"/)
    expect(src).toMatch(/integrations_unavailable/)
    expect(src).toMatch(/setIntegrationsUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/integrations`\)\.catch\(\(\) => null\)/)
  })
})
