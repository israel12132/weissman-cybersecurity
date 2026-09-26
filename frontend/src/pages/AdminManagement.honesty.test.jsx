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
    expect(src).toMatch(
      /const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(usersUnavailable\) return/,
    )
    expect(src).toMatch(/exportDisabled=\{usersUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-edit user modal after a failed users GET', () => {
    expect(src).toMatch(/\{editingUser && !usersUnavailable && \(/)
    // The edit dialog's trap must be off once the users GET failed; it may additionally be
    // suspended while the step-up (re-auth) modal is layered on top — both keep the invariant.
    expect(src).toMatch(
      /useFocusTrap\(editModalRef, !!editingUser && !usersUnavailable(?: && !stepUpModalProps\.open)?\)/,
    )
    expect(src).toMatch(
      /setUsersUnavailable\(true\)\n {6}setError\(err\.message \|\| t\('pages\.adminManagement\.load_failed'\)\)/,
    )
    expect(src).not.toMatch(/setUsersUnavailable\(true\)\n {6}setEditingUser/)
  })

  it('mutes leftover leftover-GET users CSV after a failed users GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/admin\/users'\)/)
    expect(src).toMatch(
      /const handleExportUsersCsv = useCallback\(\(\) => \{\n {4}if \(usersUnavailable\) return/,
    )
    expect(src).toMatch(/onClick=\{handleExportUsersCsv\}/)
    expect(src).toMatch(
      /\{!usersUnavailable && \(\s*<Button variant="unstyled"\s*id="adminmgmt-export-users-btn"/,
    )
    expect(src).toMatch(
      /downloadCsv\(rows, \['Email', 'Role', 'Superadmin', 'Active'\], 'weissman-users'\)/,
    )
    expect(src).not.toMatch(/onClick=\{\(\) => \{\s*const rows = users\.map/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed users GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/admin\/users'\)/)
    expect(src).toMatch(
      /const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(usersUnavailable\) return/,
    )
    expect(src).toMatch(/onExport=\{usersUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{usersUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{loadUsers\}/)
    expect(src).toMatch(/setError\(d\.detail \|\| 'Failed to create user'\)/)
    expect(src).not.toMatch(/Failed to create user[\s\S]{0,80}setUsersUnavailable/)
    expect(src).not.toMatch(/setUsersUnavailable\(true\)\n {6}setUsers\(/)
  })
})
