import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (k === 'components.cockpitTabs.execKpiStrip.micro_severity_ticker' && d && typeof d === 'object') {
        return `Micro-Severity ${d.score}`
      }
      if (k === 'components.cockpitTabs.execKpiStrip.fair_sle_footer' && d && typeof d === 'object') {
        return `SLE ${d.sle}`
      }
      if (k === 'components.cockpitTabs.execKpiStrip.agents_count' && d && typeof d === 'object') {
        return `${d.online}/${d.registered} agt`
      }
      if (typeof d === 'string') return d
      if (d && typeof d === 'object' && d.defaultValue) return d.defaultValue
      return k
    },
    i18n: { language: 'en' },
  }),
}))

const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../EngineRealityBadge', () => ({
  EngineRealitySummary: () => <span>engines</span>,
}))

const clientState = { selectedClientId: 7 }
vi.mock('../../context/ClientContext', () => ({
  useClient: () => clientState,
}))

import ExecKpiStrip from './ExecKpiStrip.jsx'

const priced = {
  ok: true,
  security_score: 73,
  headline_risk: {
    method: 'fair_usd_blast_radius',
    priced: true,
    ale_annualised_usd: 180_000,
    sle_worst_usd: 98_000,
  },
  scoring: {
    method: 'fair_usd_blast_radius',
    fair: {
      method: 'fair_usd_blast_radius',
      priced: true,
      ale_annualised_usd: 180_000,
      sle_worst_usd: 98_000,
    },
    micro_severity: {
      method: 'micro_severity_product',
      score: 73,
      not_residual_financial_risk: true,
    },
  },
  severity: { critical: 1, high: 2, medium: 3, low: 0, info: 0 },
  agents: { online: 1, registered: 2, stale: 1 },
  jobs: { pending: 0, running: 1, completed_24h: 4, failed_24h: 0 },
  assets: { total_clients: 1, with_findings: 1 },
  trend: { discovered: [1, 2], resolved: [0, 1] },
  mttr_hours: 4.2,
  last_updated_unix: Math.floor(Date.now() / 1000),
}

describe('ExecKpiStrip FAIR headline', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    clientState.selectedClientId = 7
  })
  afterEach(cleanup)

  it('shows FAIR ALE as the cockpit headline and labels Micro-Severity as SOC ranking', async () => {
    apiFetch.mockResolvedValue(priced)
    render(
      <MemoryRouter>
        <ExecKpiStrip />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('$180.0K')).toBeTruthy()
    })
    expect(apiFetch).toHaveBeenCalledWith('/api/dashboard/exec-kpis?client_id=7')
    expect(screen.getByText('components.cockpitTabs.execKpiStrip.fair_ale')).toBeTruthy()
    expect(screen.getByText('Micro-Severity 73')).toBeTruthy()
    expect(screen.queryByText('$73')).toBeNull()
  })

  it('fail-visible cannot-price when FAIR inputs are missing', async () => {
    apiFetch.mockResolvedValue({
      ...priced,
      headline_risk: {
        method: 'fair_usd_blast_radius',
        priced: false,
        cannot_price_reason: 'Cannot price — FAIR inputs are empty',
        ale_annualised_usd: null,
      },
      scoring: {
        method: 'fair_usd_blast_radius',
        fair: { method: 'fair_usd_blast_radius', priced: false, ale_annualised_usd: null },
        micro_severity: { method: 'micro_severity_product', score: 99 },
      },
    })
    render(
      <MemoryRouter>
        <ExecKpiStrip />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('components.cockpitTabs.execKpiStrip.cannot_price')).toBeTruthy()
    })
    expect(screen.queryByText('$180.0K')).toBeNull()
    expect(screen.queryByText('$0')).toBeNull()
    expect(screen.getByText(/Cannot price — FAIR inputs are empty/)).toBeTruthy()
  })
})
