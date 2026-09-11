import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../lib/launchEngineScan', () => ({
  launchEngineScan: vi.fn(async () => ({ ok: true, data: {} })),
}))

vi.mock('./PageShell', () => ({
  __esModule: true,
  default: ({ title, children, actions }) => (
    <div>
      <h1>{title}</h1>
      <div>{actions}</div>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: ({ onRefresh, onExport }) => (
    <div>
      <button type="button" onClick={onRefresh}>refresh</button>
      <button type="button" onClick={onExport}>export</button>
    </div>
  ),
}))
vi.mock('../components/ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title }) => <div>{title}</div>,
}))
vi.mock('../components/ui/EvidenceNotice', () => ({
  __esModule: true,
  default: ({ children }) => <p>{children}</p>,
}))
vi.mock('../components/ui/ExecutiveWidget', () => ({
  __esModule: true,
  default: ({ label, value }) => <div>{label}:{value}</div>,
}))
vi.mock('../components/ui/DataTable', () => ({
  __esModule: true,
  default: ({ data }) => (
    <table>
      <tbody>
        {data.map((r) => (
          <tr key={r.id} data-testid={`sku-row-${r.id}`}>
            <td>{r.panw_sku}</td>
            <td>{r.verdict}</td>
          </tr>
        ))}
      </tbody>
    </table>
  ),
}))
vi.mock('../components/ui/Skeleton', () => ({ SkeletonWidgetGrid: () => <div>skel</div> }))
vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}))
vi.mock('../lib/exportFindingsCsv', () => ({ downloadCsv: vi.fn() }))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 9, name: 'Acme', domains: ['acme.test'] }],
    selectedClientId: 9,
    setSelectedClientId: vi.fn(),
  }),
}))

import PanwDisplacement from './PanwDisplacement.jsx'

const PAYLOAD = {
  category_truth: 'Weissman is live-evidence assessment',
  unique_moat: { engine_id: 'exposure_schism_fusion', why_panw_cannot_copy: 'Xpanse inventories' },
  code_absences: ['scim', 'chronicle_siem_adapter'],
  counts: { live_win: 1, live_partial: 1, live_gap: 1, unproven: 1 },
  live_connectors: {
    aws_role_configured: true,
    azure_configured: false,
    gcp_project_configured: false,
    sso_idp_count: 2,
    enrolled_agents_online: 0,
    enrolled_agents_total: 1,
    soar_providers: ['jira'],
    surface: { snapshot_count: 2, baseline_only: false, added: 1 },
    first_mover_nerve: { certstream_connected: true, certstream_enabled: true, oast_configured: true },
  },
  skus: [
    { id: 'prisma_cloud', panw_sku: 'Prisma Cloud', role: 'overlap', verdict: 'live_partial', weissman_engines: [{ id: 'cloud_posture' }], honest_gap: 'AWS only' },
    { id: 'prisma_access', panw_sku: 'Prisma Access / NGFW', role: 'non_goal', verdict: 'non_goal', weissman_engines: [], honest_gap: 'not a firewall' },
  ],
}

describe('PanwDisplacement', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockResolvedValue(PAYLOAD)
  })

  it('loads live SKU verdicts and does not invent a firewall win', async () => {
    render(
      <MemoryRouter>
        <PanwDisplacement />
      </MemoryRouter>,
    )
    await waitFor(() => expect(apiFetch).toHaveBeenCalled())
    expect(apiFetch.mock.calls[0][0]).toContain('/api/competitive/panw-displacement')
    expect(apiFetch.mock.calls[0][0]).toContain('client_id=9')
    expect(await screen.findByText('Prisma Cloud')).toBeTruthy()
    expect(screen.getByText('live_partial')).toBeTruthy()
    expect(screen.getByText('Prisma Access / NGFW')).toBeTruthy()
    expect(screen.getByText('non_goal')).toBeTruthy()
    expect(screen.getByText('scim')).toBeTruthy()
    expect(screen.getByText('exposure_schism_fusion')).toBeTruthy()
    expect(screen.getByText('Weissman is live-evidence assessment')).toBeTruthy()
  })

  it('filters SKUs by search', async () => {
    render(
      <MemoryRouter>
        <PanwDisplacement />
      </MemoryRouter>,
    )
    await screen.findByTestId('sku-row-prisma_cloud')
    const input = screen.getByTestId('sku-search')
    fireEvent.change(input, { target: { value: 'prisma_access' } })
    await waitFor(() => {
      expect(screen.queryByTestId('sku-row-prisma_cloud')).toBeNull()
    })
    expect(screen.getByTestId('sku-row-prisma_access')).toBeTruthy()
    expect(screen.getByText('Prisma Access / NGFW')).toBeTruthy()
  })
})
