import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../hooks/useVisiblePolling', () => ({
  useVisiblePolling: () => {},
}))

import RateLimitStatus from './RateLimitStatus.jsx'

describe('RateLimitStatus', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint healthy 0/max when the rate-limit API is down', async () => {
    apiFetch.mockRejectedValue(new Error('store down'))
    render(<RateLimitStatus />)
    expect(await screen.findByTestId('rate-limit-unavailable')).toBeTruthy()
    expect(screen.queryByText(/0\/24/)).toBeNull()
    expect(screen.queryByText('components.intelWidgets.rateLimitStatus.warning')).toBeNull()
  })

  it('renders live usage when the API returns limits', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      limits: {
        scans: { current: 3, max: 24, resetIn: 12 },
        logins: { current: 1, max: 8, resetIn: 40 },
        api: { current: 2, max: 30, resetIn: 1 },
      },
    })
    render(<RateLimitStatus />)
    expect(await screen.findByText('3/24')).toBeTruthy()
    expect(screen.queryByTestId('rate-limit-unavailable')).toBeNull()
  })
})
