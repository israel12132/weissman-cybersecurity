import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'ClientOnboardingWizard.jsx'), 'utf8')
const hook = readFileSync(join(here, '../../hooks/useEngineRequirements.js'), 'utf8')
const host = readFileSync(join(here, '../../pages/ClientNew.jsx'), 'utf8')

describe('ClientOnboardingWizard live-only truth', () => {
  it('does not paint unconfirmed 0% when leftover leftover-GET catalog stays initial null', () => {
    expect(hook).toMatch(/apiFetch\('\/api\/engines\/requirements'\)/)
    expect(hook).toMatch(/apiFetch\('\/api\/onboarding\/tenant-status'\)/)
    expect(hook).toMatch(/} catch \(e\) \{\n {6}setError\(e\.message \|\| 'Failed to load requirements'\)\n {4}}/)
    expect(hook).not.toMatch(/catch \(e\) \{\s*setError\([^)]+\)\s*setCatalog\(null\)/)
    expect(src).toMatch(/const catalogUnavailable = !catalog && !!loadError/)
    expect(src).toMatch(/\{catalogUnavailable \? '—' : `\$\{readiness\.percent\}%`\}/)
    expect(src).toMatch(/width: catalogUnavailable \? '0%' : `\$\{readiness\.percent\}%`/)
    expect(src).toMatch(/data-testid="client-onboarding-catalog-unavailable"/)
    expect(src).toMatch(/catalog_unavailable_title/)
    expect(src).not.toMatch(/<div className="text-lg font-semibold text-white">\{readiness\.percent\}%<\/div>/)
  })

  it('does not latch catalog unavailable from POST /api/clients create fail', () => {
    expect(host).toMatch(/apiFetch\('\/api\/clients', \{\n {8}method: 'POST',/)
    expect(host).toMatch(/setError\(t\('pages\.clientNew\.create_failed', \{ detail \}\)\)/)
    expect(host).not.toMatch(/create_failed[\s\S]{0,200}setCatalog/)
    expect(src).not.toMatch(/create_failed[\s\S]{0,200}catalogUnavailable/)
    expect(src).not.toMatch(/externalError[\s\S]{0,80}catalogUnavailable/)
  })
})
