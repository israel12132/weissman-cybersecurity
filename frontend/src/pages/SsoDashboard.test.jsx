import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiGet = vi.fn()
const apiPost = vi.fn()
const apiPut = vi.fn()
const apiDelete = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  api: {
    get: (...args) => apiGet(...args),
    post: (...args) => apiPost(...args),
    put: (...args) => apiPut(...args),
    patch: vi.fn(),
    delete: (...args) => apiDelete(...args),
  },
}))
vi.mock('../lib/apiBase', () => ({
  apiUrl: (p) => p,
}))
vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanListToolbar', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (findings) => ({
    exportCsv: vi.fn(),
    filteredFindings: findings,
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))
vi.mock('../utils/confirmDialog', () => ({ confirmDialog: vi.fn(async () => true) }))

import SsoDashboard from './SsoDashboard.jsx'

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SsoDashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('SsoDashboard SCIM kill-switch', () => {
  beforeEach(() => {
    apiGet.mockImplementation(async (url) => {
      if (url === '/api/sso/idps') return { idps: [] }
      if (url === '/api/sso/scim/status') {
        return { ok: true, scim_base: '/scim/v2', active_tokens: 1, group_maps: 1, events_7d: 2, kill_switches_7d: 1, live: true }
      }
      if (url === '/api/sso/scim/tokens') {
        return { tokens: [{ id: 9, token_prefix: 'wmn_scim_aaa', label: 'entra-okta', revoked_at: null }] }
      }
      if (url === '/api/sso/scim/group-maps') {
        return { maps: [{ id: 1, group_external_id: 'Security-Analysts', group_display_name: 'Analysts', weissman_role: 'analyst' }] }
      }
      if (url === '/api/sso/scim/events') {
        return {
          live: true,
          events: [{ id: 3, action: 'kill_switch', user_email: 'leaver@example.com', sessions_revoked: 2, created_at: '2026-09-11T12:00:00Z' }],
        }
      }
      return {}
    })
    apiPost.mockResolvedValue({ token: 'wmn_scim_secret', token_prefix: 'wmn_scim_' })
    apiPut.mockResolvedValue({ ok: true, count: 1 })
  })
  afterEach(cleanup)

  it('renders live SCIM tape from GET /api/sso/scim/events', async () => {
    renderPage()
    expect(await screen.findByTestId('scim-kill-switch')).toBeTruthy()
    await waitFor(() => {
      expect(screen.getByText(/kill_switch/)).toBeTruthy()
      expect(screen.getByText(/leaver@example.com/)).toBeTruthy()
    })
    expect(apiGet).toHaveBeenCalledWith('/api/sso/scim/events')
    expect(apiGet).toHaveBeenCalledWith('/api/sso/scim/status')
  })

  it('mints a SCIM token through POST /api/sso/scim/tokens', async () => {
    renderPage()
    await screen.findByTestId('scim-kill-switch')
    fireEvent.click(screen.getByText('pages.ssoDashboard.scim_mint'))
    await waitFor(() => {
      expect(apiPost).toHaveBeenCalledWith('/api/sso/scim/tokens', { label: 'entra-okta' })
      expect(screen.getByText('wmn_scim_secret')).toBeTruthy()
    })
  })
})
