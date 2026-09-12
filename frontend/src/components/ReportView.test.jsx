import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  Trans: ({ children }) => children,
}))

vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))

vi.mock('./ui/StandaloneLabShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))

vi.mock('../lib/apiBase', () => ({
  apiUrl: (p) => p,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import ReportView from './ReportView.jsx'

describe('ReportView', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint total_findings zero when clients or findings APIs are down', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, detail: 'store down' })
    render(<ReportView />)
    expect(await screen.findByTestId('report-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.reportView.total_findings')).toBeNull()
    expect(screen.queryByText('components.reportView.no_sealed_run')).toBeNull()
  })

  it('renders live findings from the {ok, findings} envelope, not a raw array', async () => {
    apiFetch
      .mockResolvedValueOnce([{ id: 7, name: 'Acme' }])
      .mockResolvedValueOnce({
        ok: true,
        findings: [{ client: '7', title: 'live finding', verified: true }],
        total: 1,
      })
      .mockResolvedValueOnce({ audit_root_hash: 'abc123' })
    render(<ReportView />)
    expect(await screen.findByText('components.reportView.total_findings')).toBeTruthy()
    expect(screen.queryByTestId('report-unavailable')).toBeNull()
  })
})
