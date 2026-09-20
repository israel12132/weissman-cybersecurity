import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

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

vi.mock('framer-motion', () => ({
  motion: new Proxy(
    {},
    {
      get: (_t, tag) => (props) => {
        const Tag = String(tag)
        const { initial, animate, transition, whileHover, whileTap, ...rest } = props
        return <Tag {...rest} />
      },
    },
  ),
}))

import CommandHero from './CommandHero.jsx'

describe('CommandHero honesty', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('does not paint a score when exec-kpis is store-down', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      security_score: null,
      trend: null,
      detail: 'store down',
    })
    render(<CommandHero />)
    expect(await screen.findByTestId('exec-kpi-unavailable')).toBeTruthy()
    expect(screen.queryByText(/\/100/)).toBeNull()
    expect(screen.queryByText('components.cockpitTabs.execKpiStrip.live')).toBeNull()
  })

  it('coalesces silent polls instead of abort-restarting every 15s', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'CommandHero.jsx'), 'utf8')
    expect(src).toMatch(/useVisiblePolling/)
    expect(src).toMatch(/silent && inflightRef/)
    expect(src).not.toMatch(/setInterval\(refresh/)
  })
})
