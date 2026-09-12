import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { FirstMoverDeltaPanel } from './AttackSurfaceManagement.jsx'

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
  afterEach(cleanup)

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
        nerve={{ certstream: { connected: true, enabled: true }, oast: { configured: true }, nvd: { api_key_configured: false } }}
      />,
    )
    expect(screen.getByText('shop.example.com')).toBeTruthy()
    expect(screen.getByText('www.example.com')).toBeTruthy()
    expect(screen.getByText('old.example.com')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_title')).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.first_mover_fusion/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.nerve_certstream/)).toBeTruthy()
  })

  it('fail-visibly reports last OAST callback instead of looking live when none exist', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], removed: [], changed: [] }}
        loading={false}
        hunting={false}
        fusionHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        huntDisabled
        nerve={{
          certstream: { connected: false, enabled: false },
          oast: { configured: false, last_callback_at: null },
          nvd: { api_key_configured: false },
        }}
      />,
    )
    expect(screen.getByText(/pages.attackSurfaceManagement.nerve_oast_last/)).toBeTruthy()
    expect(screen.getAllByText(/pages.attackSurfaceManagement.nerve_oast_none/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/pages.attackSurfaceManagement.nerve_off/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/pages.attackSurfaceManagement.nerve_live/)).toBeNull()
  })

  it('does not label OAST live when the domain is set but no callback exists', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], removed: [], changed: [] }}
        loading={false}
        hunting={false}
        fusionHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        huntDisabled
        nerve={{
          certstream: { connected: false, enabled: false },
          oast: { configured: true, last_callback_at: null },
          nvd: { api_key_configured: false },
        }}
      />,
    )
    expect(screen.getByText(/pages.attackSurfaceManagement.nerve_oast_idle/)).toBeTruthy()
    expect(screen.queryByText(/pages.attackSurfaceManagement.nerve_live/)).toBeNull()
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
    expect(screen.queryByText('pages.attackSurfaceManagement.first_mover_added')).toBeNull()
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
    expect(screen.queryByTestId('first-mover-nerve-unavailable')).toBeNull()
  })

  it('does not paint nerve_off when the first-mover nerve API is unavailable', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], removed: [], changed: [] }}
        loading={false}
        hunting={false}
        onHunt={() => {}}
        huntDisabled
        nerve={{ unavailable: true, ok: false }}
      />,
    )
    expect(screen.getByTestId('first-mover-nerve-unavailable')).toBeTruthy()
    expect(screen.queryByText(/pages.attackSurfaceManagement.nerve_off/)).toBeNull()
    expect(screen.queryByText(/pages.attackSurfaceManagement.nerve_live/)).toBeNull()
  })
})
