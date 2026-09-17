import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  Link: ({ children }) => <a>{children}</a>,
  useParams: () => ({ id: '7' }),
}))
vi.mock('./PageShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}))
vi.mock('../components/engine/ShellScanActions', () => ({ default: () => null }))
vi.mock('../components/engine/WeissmanListToolbar', () => ({ default: () => null }))
vi.mock('../components/ui/EmptyState', () => ({ default: () => null }))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: (list) => ({
    exportCsv: vi.fn(),
    filteredFindings: list,
    searchQuery: '',
    setSearchQuery: vi.fn(),
  }),
}))
vi.mock('../utils/confirmDialog', () => ({ confirmDialog: vi.fn() }))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }),
}))
vi.mock('../components/ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
vi.mock('../lib/apiBase', () => ({ apiUrl: (p) => p }))
const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import ClientEngagements from './ClientEngagements.jsx'

describe('ClientEngagements', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint no-engagements theater when the list API is unavailable', async () => {
    apiFetch.mockImplementation((url) => {
      const u = String(url)
      if (u === '/api/clients/7') return Promise.resolve({ id: 7, name: 'Acme' })
      if (u.includes('/engagements')) {
        return Promise.resolve({ ok: false, unavailable: true, engagements: [], detail: 'store down' })
      }
      return Promise.resolve({})
    })
    render(<ClientEngagements />)
    expect(await screen.findByTestId('engagements-unavailable')).toBeTruthy()
    expect(screen.queryByText('pages.clientEngagements.empty')).toBeNull()
  })
})
