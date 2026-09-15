import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))

vi.mock('./ui/StandaloneLabShell', () => ({
  __esModule: true,
  default: ({ children }) => <div>{children}</div>,
}))

vi.mock('./ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))

vi.mock('../hooks/useFocusTrap', () => ({ default: () => {} }))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import CICDThreatMatrix from './CICDThreatMatrix.jsx'

describe('CICDThreatMatrix', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not treat a store-down clients API as a missing client', async () => {
    apiFetch.mockImplementation((url) => {
      if (url === '/api/clients') {
        return Promise.resolve({ ok: false, unavailable: true, clients: [], detail: 'store down' })
      }
      if (String(url).includes('/cicd-findings')) {
        return Promise.resolve({ findings: [] })
      }
      return Promise.resolve({})
    })
    render(<CICDThreatMatrix />)
    expect(await screen.findByTestId('cicd-clients-unavailable')).toBeTruthy()
  })

  it('does not paint a clean pipeline when findings fail to load', async () => {
    apiFetch.mockImplementation((url) => {
      if (String(url).includes('/cicd-findings')) {
        return Promise.resolve({ ok: false, unavailable: true, findings: [], detail: 'store down' })
      }
      if (url === '/api/clients') return Promise.resolve([])
      return Promise.resolve({})
    })
    render(<CICDThreatMatrix />)
    expect(await screen.findByTestId('cicd-lab-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.tools.cicdThreatMatrix.no_findings')).toBeNull()
    expect(screen.getAllByTestId('cicd-stage-unconfirmed').length).toBe(4)
  })
})
