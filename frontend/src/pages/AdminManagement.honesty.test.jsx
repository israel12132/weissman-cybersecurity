import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AdminManagement.jsx'),
  'utf8',
)

describe('AdminManagement live-only truth', () => {
  it('does not paint no-users when the identity store is down', () => {
    expect(src).toMatch(/\) : usersUnavailable \? \(/)
    expect(src).toMatch(/data-testid="admin-users-unavailable"/)
    expect(src).toMatch(/setUsersUnavailable\(true\)/)
  })

  it('does not paint leftover leftover-last-updated after a failed users GET', () => {
    expect(src).toMatch(/lastUpdated=\{usersUnavailable \? null : lastUpdated\}/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(usersUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{usersUnavailable \|\| !filteredFindings\.length\}/)
  })
})
