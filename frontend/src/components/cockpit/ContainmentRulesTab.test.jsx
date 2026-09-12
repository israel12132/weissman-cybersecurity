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
  dualControlBody: (b) => b,
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import ContainmentRulesTab from './ContainmentRulesTab.jsx'

describe('ContainmentRulesTab', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint no-rules theater when the rules API is down', async () => {
    apiFetch.mockRejectedValue(new Error('store down'))
    render(<ContainmentRulesTab />)
    expect(await screen.findByTestId('containment-rules-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.containmentRules.noRules')).toBeNull()
  })

  it('treats ok:false unavailable JSON as store-down, not an empty rule set', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, rules: [], detail: 'store down' })
    render(<ContainmentRulesTab />)
    expect(await screen.findByTestId('containment-rules-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.containmentRules.noRules')).toBeNull()
  })
})
