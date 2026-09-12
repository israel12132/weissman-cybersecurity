import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

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
})
