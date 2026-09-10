import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
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
        onHunt={() => {}}
        huntDisabled={false}
      />,
    )
    expect(screen.getByText('shop.example.com')).toBeTruthy()
    expect(screen.getByText('www.example.com')).toBeTruthy()
    expect(screen.getByText('old.example.com')).toBeTruthy()
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_title')).toBeTruthy()
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
