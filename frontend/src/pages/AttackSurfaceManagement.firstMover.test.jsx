import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FirstMoverDeltaPanel, extraHostsFromSurfaceDiff, isSchismPanelFinding } from './AttackSurfaceManagement.jsx'

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
        schismHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        onSchism={() => {}}
        huntDisabled={false}
        nerve={{ certstream: { connected: true, enabled: true }, oast: { configured: true }, nvd: { api_key_configured: false } }}
      />,
    )
    expect(screen.getByText('shop.example.com')).toBeTruthy()
    expect(screen.getByText('www.example.com')).toBeTruthy()
    expect(screen.getByText('old.example.com')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_title')).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.first_mover_fusion/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.first_mover_schism/)).toBeTruthy()
    expect(screen.getByText(/pages.attackSurfaceManagement.nerve_certstream/)).toBeTruthy()
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

  it('renders fused schism findings and hides first-mover inventory rows', () => {
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 1, added: [{ fqdn: 'shop.example.com', evidence: 'new host' }], changed: [], removed: [] }}
        loading={false}
        hunting={false}
        fusionHunting={false}
        schismHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        onSchism={() => {}}
        huntDisabled={false}
        schismFindings={[
          { title: 'New internet-facing host shop.example.com', severity: 'medium', category: 'added', type: 'first_mover_surface_delta' },
          {
            title: 'HTTP/1.1↔HTTP/2 schism auth bypass',
            severity: 'critical',
            fusion: 'exposure_schism_fusion',
            fusion_engine: 'liminal_boundary',
            category: 'boundary_protocol_bypass',
            type: 'exposure_schism_fusion',
          },
        ]}
      />,
    )
    expect(screen.getByText('HTTP/1.1↔HTTP/2 schism auth bypass')).toBeTruthy()
    expect(screen.queryByText('New internet-facing host shop.example.com')).toBeNull()
  })

  it('extracts extra_hosts from live surface-diff added+changed only', () => {
    expect(extraHostsFromSurfaceDiff({
      added: [{ fqdn: 'shop.example.com' }],
      changed: [{ fqdn: 'www.example.com' }],
      removed: [{ fqdn: 'old.example.com' }],
    })).toEqual(['shop.example.com', 'www.example.com'])
    expect(extraHostsFromSurfaceDiff({ unavailable: true, added: [{ fqdn: 'shop.example.com' }] })).toEqual([])
    expect(isSchismPanelFinding({ type: 'first_mover_surface_delta', category: 'added' })).toBe(false)
    expect(isSchismPanelFinding({ fusion: 'exposure_schism_fusion', title: 'idle' })).toBe(true)
  })
})
