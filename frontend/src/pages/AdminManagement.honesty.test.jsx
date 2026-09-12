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
    expect(src).toMatch(/usersUnavailable && users\.length === 0/)
    expect(src).toMatch(/data-testid="admin-users-unavailable"/)
    expect(src).toMatch(/setUsersUnavailable\(true\)/)
  })
})
