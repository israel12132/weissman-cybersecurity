import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({
    selectedClientId: '7',
    selectedClient: { id: '7', name: 'Acme' },
    refreshClients: vi.fn(),
  }),
}))
vi.mock('../ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import ComplianceDashboardTab from './ComplianceDashboardTab.jsx'

describe('ComplianceDashboardTab', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not claim no framework data when posture API is unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, frameworks: [], detail: 'store down' })
    render(<ComplianceDashboardTab />)
    expect(await screen.findByTestId('compliance-posture-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.complianceDashboard.noFrameworkData')).toBeNull()
  })
})
