import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title }) => <div>{title}</div>,
}))

import FirstSeenHitsPanel from './FirstSeenHitsPanel.jsx'

describe('FirstSeenHitsPanel', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('renders pre-NVD hits and never titles listed rows as first-seen', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      first_seen_count: 1,
      listed_count: 1,
      skipped_count: 0,
      nvd_api_key_configured: true,
      hits: [
        {
          id: 1,
          package_name: 'openssl',
          version_spec: '1.1.1',
          osv_id: 'GHSA-xxxx',
          cve_id: null,
          nvd_status: 'absent_cve',
          claimed_first_seen: true,
        },
        {
          id: 2,
          package_name: 'lodash',
          version_spec: '4.17.21',
          osv_id: 'GHSA-yyyy',
          cve_id: 'CVE-2021-23337',
          nvd_status: 'listed',
          claimed_first_seen: false,
        },
      ],
    })
    render(<FirstSeenHitsPanel clientId={3} />)
    expect(await screen.findByText(/openssl@1.1.1/)).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_seen_badge_pre')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_seen_status_listed')).toBeTruthy()
    const listedRow = screen.getByTestId('first-seen-row-2')
    expect(listedRow.textContent).not.toMatch(/first_seen_badge_pre/)
    expect(apiFetch).toHaveBeenCalledWith('/api/clients/3/first-seen-hits')
  })

  it('does not paint an empty-success inventory when the store is down', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      hits: [],
      first_seen_count: 0,
      listed_count: 0,
      detail: 'service unavailable',
    })
    render(<FirstSeenHitsPanel clientId={3} />)
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.queryByText('pages.attackSurfaceManagement.first_seen_empty_title')).toBeNull()
    expect(screen.queryByText('pages.attackSurfaceManagement.first_seen_pre_nvd')).toBeNull()
  })
})
