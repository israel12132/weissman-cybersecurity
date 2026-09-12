import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k, d) => (typeof d === 'string' ? d : k), i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))
vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, actions, children }) => (
    <div>
      <h1>{title}</h1>
      <div>{actions}</div>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))

import CompetitiveDelta, { deltaLaneRows } from './CompetitiveDelta.jsx'

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CompetitiveDelta />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('CompetitiveDelta', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders live lanes from GET /api/competitive-delta and does not invent PAN-OS replacement', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      live: true,
      not_a_panos_replacement: true,
      panos_posture: 'companion evidence plane — does not replace Strata',
      engines: { total_ids: 585 },
      fusion_engines: 15,
      ot_safety: { in_production_catalog: true, catalogued_ids: ['ot_passive_active_safety'] },
      ops_env: { oast_configured: false, nvd_api_key_present: false, vngfw_admin_configured: false },
      tenant: { endpoint_agents_enrolled: 0, sso_idps_active: 1, sso_configured: true },
      revision: {
        campaign_fabric: { on_this_revision: false, status: 'not_on_this_revision', detail: 'open PRs' },
        proof_artifacts: { on_this_revision: false, status: 'not_on_this_revision' },
      },
      moat: {
        unmatched_stack: true,
        engines_total: 585,
        lanes_covered: 17,
        lanes_total: 17,
        lanes: [
          {
            id: 'ot_ics',
            title: 'OT/ICS live protocol FSM',
            live_engine_count: 34,
            covered: true,
            beats: 'Claroty passive',
          },
          {
            id: 'network_prevention',
            title: 'NGFW / SASE / CASB posture',
            live_engine_count: 4,
            covered: true,
            beats: 'not a PAN-OS replacement',
          },
        ],
        market_research: {
          live: false,
          clusters: [
            {
              cluster: 'network_prevention_sase',
              vendors: ['Palo Alto Networks Strata'],
              owns: 'inline packet-path NGFW',
              lacks: 'OT FSM',
              weissman_posture: 'not a PAN-OS / Strata replacement',
            },
          ],
        },
      },
    })
    renderPage()
    expect(await screen.findByTestId('panos-posture')).toBeInTheDocument()
    expect(screen.getByText('OT/ICS live protocol FSM')).toBeInTheDocument()
    expect(screen.getByText('NGFW / SASE / CASB posture')).toBeInTheDocument()
    expect(screen.getByTestId('campaign-fabric').textContent).toMatch(/not_on_revision|not_on_this_revision|open PRs/)
    expect(screen.getByTestId('market-research')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/competitive-delta')
  })

  it('surfaces an error when the delta endpoint fails', async () => {
    apiFetch.mockRejectedValue(new Error('backend exploded'))
    renderPage()
    expect(await screen.findByText('backend exploded')).toBeInTheDocument()
  })

  it('maps lanes to export rows', () => {
    const rows = deltaLaneRows([
      { id: 'ot_ics', title: 'OT', live_engine_count: 2, covered: true, beats: 'Claroty', sample_ids: ['scada_ics'] },
    ])
    expect(rows[0]).toEqual(['ot_ics', 'OT', 2, 'live', 'Claroty', 'scada_ics'])
  })
})
