import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: '7' }),
}))
vi.mock('../../utils/destructiveConfirm', () => ({
  destructiveHeaders: () => ({}),
  dualControlBody: (a, b, c) => c,
}))
vi.mock('../ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import AutoHealTab from './AutoHealTab.jsx'

describe('AutoHealTab', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint no-requests theater when heal-requests API is unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, requests: [], detail: 'store down' })
    render(<AutoHealTab />)
    expect(await screen.findByTestId('auto-heal-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.autoHeal.noRequests')).toBeNull()
  })

  it('surfaces truncated heal history instead of a complete inventory', async () => {
    apiFetch.mockResolvedValue({
      requests: [{ id: 1, finding_id: 'CVE-1', verification_status: 'verified' }],
      truncated: true,
    })
    render(<AutoHealTab />)
    expect(await screen.findByTestId('auto-heal-truncated')).toBeTruthy()
    expect(screen.queryByTestId('auto-heal-unavailable')).toBeNull()
  })

  it('does not look idle when auto-heal trigger is refused', async () => {
    apiFetch.mockImplementation((url, opts) => {
      if (opts?.method === 'POST') {
        return Promise.resolve({ ok: false, unavailable: true, detail: 'store down' })
      }
      return Promise.resolve({ requests: [] })
    })
    render(<AutoHealTab />)
    const finding = await screen.findByPlaceholderText('components.cockpitTabs.autoHeal.findingId')
    fireEvent.change(finding, { target: { value: 'CVE-1' } })
    fireEvent.click(screen.getByText('components.cockpitTabs.autoHeal.verifyButton'))
    expect(await screen.findByTestId('auto-heal-action-failed')).toBeTruthy()
  })
})
