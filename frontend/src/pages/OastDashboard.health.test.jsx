import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => (d && d.count != null ? `${k}:${d.count}` : k),
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
}))

import OastHealthStrip from '../components/oast/OastHealthStrip.jsx'

describe('OastHealthStrip', () => {
  afterEach(cleanup)

  it('fail-visibly reports a missing listener instead of looking live', () => {
    render(
      <OastHealthStrip
        health={{ configured: false, domain: '', last_callback_at: null, callback_count: 0 }}
      />,
    )
    const strip = screen.getByTestId('oast-health-strip')
    expect(strip.textContent).toMatch(/health_missing/)
    expect(strip.textContent).toMatch(/health_none/)
    expect(strip.textContent).not.toMatch(/health_configured/)
  })

  it('does not look live when the domain is set but no callback has arrived', () => {
    render(
      <OastHealthStrip
        health={{
          configured: true,
          domain: 'oast.example.test',
          last_callback_at: null,
          callback_count: 0,
        }}
      />,
    )
    const strip = screen.getByTestId('oast-health-strip')
    expect(strip.getAttribute('data-live')).toBe('false')
    expect(strip.textContent).toMatch(/health_idle/)
    expect(strip.textContent).not.toMatch(/health_configured/)
    expect(strip.className).toMatch(/amber/)
  })

  it('shows last callback when the listener is actually configured', () => {
    render(
      <OastHealthStrip
        health={{
          configured: true,
          domain: 'oast.example.test',
          last_callback_at: '2026-09-11T12:00:00Z',
          callback_count: 3,
        }}
      />,
    )
    expect(screen.getByText(/oast.example.test/)).toBeTruthy()
    expect(screen.getByText(/2026-09-11T12:00:00Z/)).toBeTruthy()
    expect(screen.getByText(/health_configured/)).toBeTruthy()
    expect(screen.getByText(/health_count:3/)).toBeTruthy()
  })

  it('renders nothing until health has been fetched', () => {
    const { container } = render(<OastHealthStrip health={null} />)
    expect(container.firstChild).toBeNull()
  })
})
