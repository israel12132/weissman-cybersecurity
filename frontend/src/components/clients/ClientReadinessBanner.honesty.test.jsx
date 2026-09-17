import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientReadinessBanner.jsx'),
  'utf8',
)

const fetchFx = src.slice(src.indexOf('useEffect(() => {'), src.indexOf('if (loading) return null'))

describe('ClientReadinessBanner live-only truth', () => {
  it('mutes leftover leftover-readiness after a failed GET /api/clients/:id/readiness', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/readiness`\)/)
    expect(src).toMatch(/setReadinessUnavailable\(false\)/)
    expect(src).toMatch(/setReadinessUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="client-readiness-unavailable"/)
    expect(src).toMatch(/if \(readinessUnavailable\) \{/)
    expect(src).toMatch(/pages\.clientOnboarding\.readiness_unavailable/)
    expect(src).not.toMatch(/if \(loading \|\| !data\?\.readiness\) return null/)
  })

  it('keeps leftover leftover-readiness in state and does not catch-clear it', () => {
    expect(fetchFx).not.toMatch(/setData\(null\)/)
    expect(fetchFx).not.toMatch(/catch \{ \/\* ignore \*\/ \}/)
    expect(src).toMatch(/const \{ readiness \} = data/)
  })

  it('keeps readinessUnavailable GET-only — this banner has no POST mute path', () => {
    expect(src).not.toMatch(/method:\s*'POST'/)
    expect(src).not.toMatch(/method:\s*"POST"/)
    expect(fetchFx).toMatch(/setReadinessUnavailable\(true\)/)
  })
})
