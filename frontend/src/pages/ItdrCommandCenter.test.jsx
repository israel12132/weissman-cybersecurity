import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 1 }),
}))

import ItdrCommandCenter from './ItdrCommandCenter.jsx'

describe('ItdrCommandCenter', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not report three armed IdPs when no tokens are stored', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/itdr/connectors') return Promise.resolve({ ok: true, connectors: {} })
      if (String(url).startsWith('/api/itdr/auth-events')) return Promise.resolve({ ok: true, events: [] })
      return Promise.resolve({})
    })
    render(
      <MemoryRouter>
        <ItdrCommandCenter />
      </MemoryRouter>,
    )
    const kpi = await screen.findByTestId('itdr-armed-providers')
    expect(kpi.getAttribute('data-live')).toBe('false')
    expect(kpi.getAttribute('data-armed')).toBe('0')
    expect(screen.getByText('pages.itdrCommandCenter.empty_unconfigured_title')).toBeTruthy()
  })

  it('counts only connectors with tokens', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/itdr/connectors') {
        return Promise.resolve({ ok: true, connectors: { entra: { access_token: 'gph' } } })
      }
      if (String(url).startsWith('/api/itdr/auth-events')) {
        return Promise.resolve({
          ok: true,
          events: [{ ts: 1, username: 'a@b', ip: '1.1.1.1', success: true, mfa_prompted: false }],
        })
      }
      return Promise.resolve({})
    })
    render(
      <MemoryRouter>
        <ItdrCommandCenter />
      </MemoryRouter>,
    )
    const kpi = await screen.findByTestId('itdr-armed-providers')
    expect(kpi.getAttribute('data-live')).toBe('true')
    expect(kpi.getAttribute('data-armed')).toBe('1')
  })
})
