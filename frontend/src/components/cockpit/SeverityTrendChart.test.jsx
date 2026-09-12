import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../../hooks/useVisiblePolling', () => ({
  useVisiblePolling: () => {},
}))

import SeverityTrendChart from './SeverityTrendChart.jsx'

describe('SeverityTrendChart', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint a zero-velocity chart when exec KPIs are unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, detail: 'store down' })
    render(<SeverityTrendChart />)
    expect(await screen.findByTestId('severity-trend-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitWidgets.severityTrendChart.discovered')).toBeNull()
  })
})
