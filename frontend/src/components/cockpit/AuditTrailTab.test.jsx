import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'

// i18n → return the key so labels are deterministic. `t` must be STABLE (as the real hook is),
// or useMemo-ed columns churn on every render.
vi.mock('react-i18next', () => {
  const t = (k) => k
  return { useTranslation: () => ({ t }) }
})

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../../utils/apiFetch', () => ({ apiFetch }))

import AuditTrailTab from './AuditTrailTab'

const SAMPLE = [
  { id: 1, timestamp: '2026-07-21T10:00:00Z', user: 'alice@acme.io', user_id: 7, action_type: 'login', ip_address: '10.0.0.5', details: 'MFA ok' },
  { id: 2, timestamp: '2026-07-21T10:05:00Z', user: 'bob@acme.io', user_id: 9, action_type: 'scan_start', ip_address: '10.0.0.6', details: 'engine=osint' },
]

beforeEach(() => {
  apiFetch.mockReset()
})
afterEach(() => cleanup())

describe('AuditTrailTab → DataTable', () => {
  it('loads audit rows and renders them through the DataTable primitive', async () => {
    apiFetch.mockResolvedValue(SAMPLE)
    render(<AuditTrailTab />)

    // Data plumbed into the DataTable → the first row's distinctive cell appears...
    await waitFor(() => expect(screen.getByText('alice@acme.io')).toBeInTheDocument())
    // ...and it rendered a real <table> with a data row per record (not a crash/empty state).
    const bodyRows = document.querySelectorAll('table tbody tr')
    expect(bodyRows.length).toBe(SAMPLE.length)
    expect(apiFetch).toHaveBeenCalledWith('/api/audit-logs')
  })

  it('shows the empty state when there are no entries', async () => {
    apiFetch.mockResolvedValue([])
    render(<AuditTrailTab />)
    await waitFor(() =>
      expect(screen.getByText('components.cockpitTabs.auditTrail.noEntries')).toBeInTheDocument(),
    )
  })
})
