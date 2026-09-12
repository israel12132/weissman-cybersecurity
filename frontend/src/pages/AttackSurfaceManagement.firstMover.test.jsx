import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FirstMoverDeltaPanel, ctKillChain } from './AttackSurfaceManagement.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}))

vi.mock('./PageShell', () => ({ __esModule: true, default: ({ children }) => <div>{children}</div> }))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanFindingsPanel', () => ({ __esModule: true, default: () => null }))
vi.mock('../hooks/useWeissmanEnginePage', () => ({
  useWeissmanEnginePage: () => ({
    filteredFindings: [],
    counts: {},
    searchQuery: '',
    setSearchQuery: () => {},
    severityFilter: 'all',
    setSeverityFilter: () => {},
    exportCsv: () => {},
    refreshFromHistory: async () => null,
    historyLoading: false,
    lastUpdated: null,
    lastJobId: null,
    setLastUpdated: () => {},
    setLastJobId: () => {},
  }),
  applyHistoryFindings: () => {},
}))
vi.mock('../hooks/useCommandCenterScan', () => ({
  useCommandCenterScan: () => ({ postScan: async () => ({ ok: false, data: {}, status: 0 }) }),
}))
vi.mock('../hooks/useLaunchEngineScan', () => ({ useSyncHubScanParams: () => {} }))
vi.mock('../utils/apiFetch', () => ({ apiFetch: async () => [] }))
vi.mock('../lib/useJobPoll', () => ({
  useJobPoll: () => {},
  resolveJobFindings: async () => [],
  uiJobStatus: (s) => s,
}))
vi.mock('../lib/clientTarget', () => ({ firstClientTarget: () => '' }))

describe('FirstMoverDeltaPanel', () => {
  it('ctKillChain reads CT fusion + OAST follow-on from nerve', () => {
    const chain = ctKillChain({
      certstream: { hunts_enqueued: 4 },
      oast: { configured: true },
      fusion: {
        ct_enqueue_engine: 'first_mover_delta_fusion',
        follow_on_engines: ['subdomain_takeover', 'jwt_attack'],
        oast_follow_on_engines: ['oast_oob', 'ssrf_advanced'],
      },
    })
    expect(chain.ctEngine).toBe('first_mover_delta_fusion')
    expect(chain.hunts).toBe(4)
    expect(chain.oastLive).toBe(true)
    expect(chain.followOn).toContain('jwt_attack')
    expect(chain.oastFollowOn).toContain('oast_oob')
  })
  it('renders added/changed/removed hosts from live surface-diff payload', () => {
    const diff = {
      current_count: 3,
      current_at: '2026-09-10T12:00:00Z',
      baseline_only: false,
      added: [{ fqdn: 'shop.example.com', evidence: 'new host A=[] CNAME=unclaimed.github.io' }],
      changed: [{ fqdn: 'www.example.com', evidence: 'A 1.1.1.1→8.8.8.8' }],
      removed: [{ fqdn: 'old.example.com', evidence: 'host disappeared' }],
    }
    render(
      <FirstMoverDeltaPanel
        diff={diff}
        loading={false}
        hunting={false}
        fusionHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        huntDisabled={false}
        nerve={{
          certstream: { connected: true, enabled: true, hunts_enqueued: 2 },
          oast: { configured: true },
          nvd: { api_key_configured: false },
          fusion: {
            ct_enqueue_engine: 'first_mover_delta_fusion',
            follow_on_engines: ['subdomain_takeover', 'jwt_attack'],
            oast_follow_on_engines: ['oast_oob'],
          },
        }}
      />,
    )
    expect(screen.getByText('shop.example.com')).toBeTruthy()
    expect(screen.getByText('www.example.com')).toBeTruthy()
    expect(screen.getByText('old.example.com')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_title')).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.first_mover_fusion/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.idp_hunt/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.skip_hunt/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.prep_hunt/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.nerve_certstream/)).toBeTruthy()
    expect(screen.getByTestId('ct-kill-chain')).toBeTruthy()
  })

  it('shows unavailable copy when the store is down without treating it as empty', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{
          unavailable: true,
          current_count: 0,
          added: [],
          removed: [],
          changed: [],
          message: 'surface diff temporarily unavailable',
        }}
        loading={false}
        hunting={false}
        onHunt={() => {}}
        huntDisabled
      />,
    )
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_unavailable')).toBeTruthy()
    expect(screen.queryByText('pages.attackSurfaceManagement.first_mover_empty')).toBeNull()
  })

  it('shows empty baseline copy when no snapshot exists', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], removed: [], changed: [] }}
        loading={false}
        hunting={false}
        onHunt={() => {}}
        huntDisabled
      />,
    )
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_empty')).toBeTruthy()
  })
})
