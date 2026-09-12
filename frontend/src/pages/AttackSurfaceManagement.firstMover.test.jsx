import { afterEach, describe, it, expect, vi } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { FirstMoverDeltaPanel, extraHostsFromSurfaceDiff, isSchismPanelFinding, schismScanBody } from './AttackSurfaceManagement.jsx'

// vitest runs with globals:false, so RTL's automatic afterEach cleanup isn't registered.
afterEach(cleanup)

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

  it('disables sibling first-mover buttons while hunt, fusion, schism, or pending is in flight', () => {
    const view = (extra) => (
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], changed: [], removed: [] }}
        loading={false}
        hunting={false}
        fusionHunting={false}
        schismHunting={false}
        pending={false}
        onHunt={() => {}}
        onFusion={() => {}}
        onSchism={() => {}}
        huntDisabled={false}
        {...extra}
      />
    )
    const { rerender, container } = render(view({ hunting: true }))
    const named = () => {
      const root = within(container)
      return {
        hunt: root.getByRole('button', { name: /first_mover_hunting|first_mover_hunt/ }),
        fusion: root.getByRole('button', { name: /first_mover_fusion|first_mover_fusing/ }),
        schism: root.getByRole('button', { name: /first_mover_schism/ }),
      }
    }
    let btns = named()
    expect(btns.hunt).toBeDisabled()
    expect(btns.fusion).toBeDisabled()
    expect(btns.schism).toBeDisabled()

    rerender(view({ fusionHunting: true }))
    btns = named()
    expect(btns.hunt).toBeDisabled()
    expect(btns.fusion).toBeDisabled()
    expect(btns.schism).toBeDisabled()

    rerender(view({ schismHunting: true }))
    btns = named()
    expect(btns.hunt).toBeDisabled()
    expect(btns.fusion).toBeDisabled()
    expect(btns.schism).toBeDisabled()

    rerender(view({ pending: true }))
    btns = named()
    expect(btns.hunt).toBeDisabled()
    expect(btns.fusion).toBeDisabled()
    expect(btns.schism).toBeDisabled()
  })

  it('posts extra_hosts from surface-diff added+changed on the schism scan body', () => {
    expect(schismScanBody({
      clientId: 7,
      target: 'acme.test',
      surfaceDiff: {
        added: [{ fqdn: 'shop.example.com' }],
        changed: [{ fqdn: 'www.example.com' }],
        removed: [{ fqdn: 'old.example.com' }],
      },
    })).toEqual({
      engine: 'exposure_schism_fusion',
      client_id: 7,
      target: 'acme.test',
      include_ct: true,
      include_http: true,
      chain_web_engines: false,
      extra_hosts: 'shop.example.com,www.example.com',
    })
    expect(schismScanBody({
      clientId: 7,
      target: 'acme.test',
      surfaceDiff: { unavailable: true, added: [{ fqdn: 'shop.example.com' }] },
    }).extra_hosts).toBeUndefined()
  })

  it('shows schism evidence and an overflow cue beyond eight live fractures', () => {
    const schismFindings = Array.from({ length: 9 }, (_, i) => ({
      title: `HTTP/2 schism ${i}`,
      severity: 'high',
      fusion: 'exposure_schism_fusion',
      evidence: i === 0 ? 'ALPN h2 vs HTTP/1.1 WWW-Authenticate mismatch' : '',
    }))
    render(
      <FirstMoverDeltaPanel
        diff={{ current_count: 0, added: [], changed: [], removed: [] }}
        loading={false}
        hunting={false}
        fusionHunting={false}
        schismHunting={false}
        onHunt={() => {}}
        onFusion={() => {}}
        onSchism={() => {}}
        huntDisabled={false}
        schismFindings={schismFindings}
      />,
    )
    expect(screen.getByText('HTTP/2 schism 0')).toBeTruthy()
    expect(screen.getByText('ALPN h2 vs HTTP/1.1 WWW-Authenticate mismatch')).toBeTruthy()
    expect(screen.queryByText('HTTP/2 schism 8')).toBeNull()
    expect(screen.getByText('pages.attackSurfaceManagement.first_mover_schism_more')).toBeTruthy()
  })
})
