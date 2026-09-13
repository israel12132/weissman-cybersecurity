import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IdentityContextManager.jsx'),
  'utf8',
)

describe('IdentityContextManager live-only truth', () => {
  it('does not paint UEBA KPI zeros when identity context is unconfirmed', () => {
    expect(src).toMatch(/data-testid="identity-context-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/clientsUnavailable/)
    expect(src).toMatch(/error \? '—'/)
    expect(src).toMatch(/error \? null : \(/)
    expect(src).toMatch(/import \{ api \} from '\.\.\/utils\/apiFetch'/)
    expect(src).toMatch(/!Array\.isArray\(data\.identities\)/)
  })

  it('does not paint leftover leftover-identity counts after a failed identity GET', () => {
    expect(src).toMatch(/count: error \? '—' : identities\.length/)
    expect(src).toMatch(/resultCount=\{error \? undefined : visibleIdentities\.length\}/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
