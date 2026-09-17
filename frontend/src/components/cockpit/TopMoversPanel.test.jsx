import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  Link: ({ children, to }) => <a href={to}>{children}</a>,
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import TopMoversPanel from './TopMoversPanel.jsx'

describe('TopMoversPanel', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint empty-mover theater when exec KPIs are unavailable', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, detail: 'store down' })
    render(<TopMoversPanel />)
    expect(await screen.findByTestId('top-movers-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitWidgets.topMoversPanel.enginesEmpty')).toBeNull()
    expect(screen.queryByText('components.cockpitWidgets.topMoversPanel.assetsEmpty')).toBeNull()
  })
})
