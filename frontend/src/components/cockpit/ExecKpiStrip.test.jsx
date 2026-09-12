import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../ui/Button', () => ({
  __esModule: true,
  default: (p) => <button type="button" {...p} />,
}))

vi.mock('../EngineRealityBadge', () => ({
  EngineRealitySummary: () => null,
}))

vi.mock('react-router', () => ({
  Link: ({ children, to }) => <a href={to}>{children}</a>,
}))

import ExecKpiStrip from './ExecKpiStrip.jsx'

describe('ExecKpiStrip honesty', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('does not paint a perfect score when exec-kpis is store-down', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      security_score: null,
      trend: null,
      detail: 'store down',
    })
    render(<ExecKpiStrip />)
    expect(await screen.findByTestId('exec-kpi-unavailable')).toBeTruthy()
    expect(screen.queryByText(/\/100/)).toBeNull()
    expect(screen.queryByText('components.cockpitTabs.execKpiStrip.live')).toBeNull()
  })
})
