import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => (typeof d === 'string' ? d : k),
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const { api } = vi.hoisted(() => ({
  api: {
    get: vi.fn(),
    patch: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('../utils/apiFetch', () => ({
  api,
  apiFetch: (...args) => api.get(...args),
  default: (...args) => api.get(...args),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, badge, children }) => (
    <div>
      <h1>{title}</h1>
      {badge && <span>{badge}</span>}
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanListToolbar', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (rows) => ({
    filteredFindings: rows,
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))
vi.mock('../lib/exportFindingsCsv', () => ({ downloadCsv: vi.fn() }))

import ScimProvisioning from './ScimProvisioning.jsx'

describe('ScimProvisioning', () => {
  beforeEach(() => {
    api.get.mockReset()
    api.post.mockReset()
    api.delete.mockReset()
  })
  afterEach(cleanup)

  it('lists live tokens and audit events from admin APIs', async () => {
    api.get.mockImplementation((url) => {
      if (url === '/api/admin/scim/tokens') {
        return Promise.resolve({
          ok: true,
          tokens: [
            {
              id: 4,
              name: 'okta-prod',
              token_prefix: 'wsm_scim_abcd1234',
              last_used_at: null,
              revoked_at: null,
              created_at: '2026-09-11T00:00:00Z',
            },
          ],
        })
      }
      if (url === '/api/admin/scim/audit') {
        return Promise.resolve({
          ok: true,
          events: [
            {
              id: 1,
              method: 'GET',
              path: '/api/scim/v2/Users',
              status: 200,
              detail: 'list',
              created_at: '2026-09-11T00:01:00Z',
            },
          ],
        })
      }
      return Promise.resolve({})
    })

    render(
      <MemoryRouter>
        <ScimProvisioning />
      </MemoryRouter>,
    )

    expect(await screen.findByText('okta-prod')).toBeInTheDocument()
    expect(screen.getByText('pages.scimProvisioning.title')).toBeInTheDocument()
    expect(screen.getByText(/\/api\/scim\/v2\/Users/)).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/admin/scim/tokens')
    expect(api.get).toHaveBeenCalledWith('/api/admin/scim/audit')
  })

  it('mints a bearer and shows the plaintext once', async () => {
    api.get.mockResolvedValue({ ok: true, tokens: [], events: [] })
    api.post.mockResolvedValue({
      ok: true,
      token: 'wsm_scim_shown_once_secret',
      shown_once: true,
    })

    render(
      <MemoryRouter>
        <ScimProvisioning />
      </MemoryRouter>,
    )
    expect(await screen.findByText('pages.scimProvisioning.empty_title')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('scim-mint-btn'))
    expect(await screen.findByText('wsm_scim_shown_once_secret')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('/api/admin/scim/tokens', { name: 'okta-prod' })
  })

  it('revokes an active token', async () => {
    api.get.mockImplementation((url) => {
      if (url === '/api/admin/scim/tokens') {
        return Promise.resolve({
          ok: true,
          tokens: [{ id: 11, name: 'entra', token_prefix: 'wsm_scim_eeee', revoked_at: null }],
        })
      }
      return Promise.resolve({ ok: true, events: [] })
    })
    api.delete.mockResolvedValue({ ok: true, revoked: true })

    render(
      <MemoryRouter>
        <ScimProvisioning />
      </MemoryRouter>,
    )
    expect(await screen.findByText('entra')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('scim-revoke-11'))
    await waitFor(() => {
      expect(api.delete).toHaveBeenCalledWith('/api/admin/scim/tokens/11')
    })
  })
})
