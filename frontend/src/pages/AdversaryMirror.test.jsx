import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

const { c2State } = vi.hoisted(() => ({ c2State: { killed: false } }))

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
  default: ({ title, children }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/FindingDrawer', () => ({
  __esModule: true,
  default: ({ finding }) => (finding ? <div data-testid="finding-drawer">{finding.title}</div> : null),
}))
vi.mock('../components/ui/DataTable', () => ({
  __esModule: true,
  default: ({ data }) => (
    <ul data-testid="findings-table">
      {(data || []).map((f, i) => (
        <li key={f.id || i}>{f.title}</li>
      ))}
    </ul>
  ),
}))
vi.mock('../hooks/useFindingsWorkbench', () => ({
  useFindingsWorkbench: () => ({ exportCsv: vi.fn() }),
}))
vi.mock('../hooks/useVisiblePolling', () => ({
  useVisiblePolling: () => {},
}))
vi.mock('../lib/useJobPoll', () => ({
  useJobPoll: () => {},
}))

const launchScan = vi.fn()
vi.mock('../hooks/useLaunchEngineScan', () => ({
  useLaunchEngineScan: () => launchScan,
}))

const toast = { success: vi.fn(), error: vi.fn() }
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast }),
}))

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 'c1', name: 'Acme', domains: ['acme.example'] }],
    selectedClientId: 'c1',
    setSelectedClientId: vi.fn(),
  }),
}))

vi.mock('../engineC2/EngineC2Boundary', () => ({
  useInsideEngineC2: () => {},
  useC2AbortSignal: () => ({
    signal: new AbortController().signal,
    killed: c2State.killed,
  }),
}))

import AdversaryMirror from './AdversaryMirror.jsx'

function renderPage() {
  return render(
    <MemoryRouter>
      <AdversaryMirror />
    </MemoryRouter>,
  )
}

describe('AdversaryMirror', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    launchScan.mockReset()
    toast.success.mockReset()
    toast.error.mockReset()
    c2State.killed = false
  })
  afterEach(cleanup)

  it('exports a page component (single JSX root)', () => {
    expect(typeof AdversaryMirror).toBe('function')
  })

  it('renders live findings, KPI total excluding info, and a single war-room tree', async () => {
    apiFetch.mockResolvedValue({
      findings: [
        { id: '1', source: 'adversary_gap_mirror', severity: 'high', title: 'Leak-site mention', target: 'acme.example' },
        { id: '2', source: 'adversary_gap_mirror', severity: 'info', title: 'Zero-hit feed note', target: 'acme.example' },
        { id: '3', source: 'osint', severity: 'high', title: 'Unrelated engine', target: 'acme.example' },
      ],
    })
    const { container } = renderPage()
    expect(await screen.findByText('Leak-site mention')).toBeInTheDocument()
    expect(screen.getByText('Zero-hit feed note')).toBeInTheDocument()
    expect(screen.queryByText('Unrelated engine')).not.toBeInTheDocument()
    expect(screen.getByText('pages.adversaryMirror.title')).toBeInTheDocument()
    expect(screen.getByText('pages.adversaryMirror.run_mirror')).toBeInTheDocument()
    expect(screen.getByText('pages.adversaryMirror.evidence_notice')).toBeInTheDocument()
    const totalLabel = screen.getByText('pages.adversaryMirror.total')
    expect(totalLabel.nextElementSibling?.textContent).toBe('1')
    expect(container.querySelectorAll('[data-testid="findings-table"]').length).toBe(1)
    expect(apiFetch).toHaveBeenCalledWith('/api/clients/c1/findings')
  })

  it('disables scan dispatch while Emergency Stop is active', async () => {
    c2State.killed = true
    apiFetch.mockResolvedValue({ findings: [] })
    renderPage()
    const run = await screen.findByRole('button', { name: 'pages.adversaryMirror.run_mirror' })
    expect(run).toBeDisabled()
    const leak = await screen.findByRole('button', { name: 'pages.adversaryMirror.run_leak' })
    const spray = screen.getByRole('button', { name: 'pages.adversaryMirror.run_spray' })
    expect(leak).toBeDisabled()
    expect(spray).toBeDisabled()
  })

  it('queues the hub-aware mirror scan when the operator runs it', async () => {
    apiFetch.mockResolvedValue({ findings: [] })
    launchScan.mockResolvedValue({ ok: true, data: { job_id: 'job-9' } })
    renderPage()
    const run = await screen.findByRole('button', { name: 'pages.adversaryMirror.run_mirror' })
    fireEvent.click(run)
    await waitFor(() => {
      expect(launchScan).toHaveBeenCalledWith(
        expect.objectContaining({
          engineId: 'adversary_gap_mirror',
          clientId: 'c1',
          target: 'https://acme.example',
        }),
      )
    })
    expect(toast.success).toHaveBeenCalledWith('pages.adversaryMirror.scan_queued')
  })
})
