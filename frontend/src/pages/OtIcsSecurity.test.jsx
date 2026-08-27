import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (k === 'pages.otIcsSecurity.safety_controls') {
        return `${d?.implemented ?? 0} / ${d?.total ?? 100} hardening controls armed`
      }
      if (k === 'pages.otIcsSecurity.safety_max_conn') return `Max ${d?.n ?? 2} conn / PLC`
      if (k === 'pages.otIcsSecurity.safety_gateway_conn') return `Gateway ${d?.n ?? 8} TCP / Unit-ID`
      if (k === 'pages.otIcsSecurity.safety_zscore') return `Isolate at Z > ${d?.z ?? 6}`
      if (k === 'pages.otIcsSecurity.safety_rst') return 'RST on abort'
      if (k === 'pages.otIcsSecurity.safety_ber_iterative') return 'Iterative BER'
      if (typeof d === 'string') return d
      return k
    },
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
  default: (...args) => apiFetch(...args),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/WeissmanFindingsPanel', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/engine/AgentRequiredGate', () => ({
  __esModule: true,
  default: ({ children }) => children,
}))
vi.mock('../hooks/useCommandCenterScan', () => ({
  useCommandCenterScan: () => ({ postScan: vi.fn() }),
}))
vi.mock('../hooks/useLaunchEngineScan', () => ({
  useHubEngineFocus: () => {},
}))
vi.mock('../lib/useJobPoll', () => ({
  useJobPoll: () => {},
  resolveJobFindings: async () => [],
  uiJobStatus: (s) => s,
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({
    filteredFindings: [],
    counts: {},
    searchQuery: '',
    setSearchQuery: vi.fn(),
    severityFilter: 'all',
    setSeverityFilter: vi.fn(),
    exportCsv: vi.fn(),
    total: 0,
  }),
}))
vi.mock('../lib/clientTarget', () => ({
  clientPrimaryTargetUrl: () => '10.0.0.8',
}))

import OtIcsSecurity from './OtIcsSecurity.jsx'

const SAFETY = {
  live: true,
  policy: {
    write_blocked: true,
    direct_operate_blocked: true,
    cpu_control_blocked: true,
    file_transfer_blocked: true,
    goose_inject_blocked: true,
    max_connections_per_host: 2,
    max_gateway_connections: 8,
    zscore_isolate_threshold: 6,
    rst_on_release: true,
    ber_iterative: true,
  },
  control_count: 100,
  protocols: [
    { id: 'modbus', port: 502, parser: 'nom_mbap', blocked: ['05', '06'] },
    { id: 'dnp3', port: 20000, parser: 'nom_dnp3_crc', blocked: ['direct_operate'] },
  ],
  events: [],
  fair: null,
}

describe('OtIcsSecurity', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation(async (url) => {
      const u = String(url)
      if (u.includes('/api/ot-ics/safety')) return SAFETY
      if (u.includes('/api/ot-ics/devices')) return { devices: [], protocols: [], findings: [] }
      if (u.includes('fingerprints')) return { fingerprints: [] }
      if (u.includes('/api/engines/history')) return { runs: [] }
      if (u === '/api/clients' || u.startsWith('/api/clients?')) {
        return [{ id: 1, name: 'Plant A', primary_domain: '10.0.0.8' }]
      }
      return {}
    })
  })
  afterEach(cleanup)

  it('renders the compiled safety interlock from GET /api/ot-ics/safety', async () => {
    render(
      <MemoryRouter>
        <OtIcsSecurity />
      </MemoryRouter>,
    )
    const panel = await screen.findByTestId('ot-safety-interlock')
    expect(panel).toBeTruthy()
    expect(panel.textContent).toMatch(/100 \/ 100/)
    expect(panel.textContent).toMatch(/modbus/i)
    expect(panel.textContent).toMatch(/dnp3/i)
    expect(panel.textContent).toMatch(/Gateway 8/)
    expect(panel.textContent).toMatch(/RST on abort/)
    expect(panel.textContent).toMatch(/Iterative BER/)
    await waitFor(() => {
      expect(apiFetch.mock.calls.some((c) => String(c[0]).includes('/api/ot-ics/safety'))).toBe(true)
    })
  })

  it('exposes the hardened OT engines including DNP3 and IEC 61850', async () => {
    render(
      <MemoryRouter>
        <OtIcsSecurity />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('ot_passive_active_safety')).toBeTruthy()
    })
    expect(screen.getByText('ot_crown_jewel_path')).toBeTruthy()
    expect(screen.getByText('dnp3_attack')).toBeTruthy()
    expect(screen.getByText('iec61850_attack')).toBeTruthy()
    expect(screen.getByText('modbus_attack')).toBeTruthy()
  })
})
