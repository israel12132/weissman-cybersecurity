import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

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
  default: ({ title, subtitle, evidence, children }) => (
    <div>
      <h1>{title}</h1>
      {subtitle && <p>{subtitle}</p>}
      {evidence && <p>{evidence}</p>}
      {children}
    </div>
  ),
}))

vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: ({ onRefresh }) => (
    <button type="button" onClick={onRefresh}>
      refresh
    </button>
  ),
}))

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 7, name: 'Acme', domains: ['app.acme.test'] }],
    selectedClientId: 7,
    setSelectedClientId: vi.fn(),
    selectedClient: { id: 7, name: 'Acme', domains: ['app.acme.test'] },
  }),
}))

const toast = { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn(), dismiss: vi.fn() }
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast }),
}))

import DiscoveryLab from './DiscoveryLab.jsx'

const CANDIDATE = {
  id: 'cand-1',
  run_id: 'run-1',
  client_id: 7,
  status: 'candidate',
  title: 'Novel parser crash on authorized host',
  technical_summary: 'fuzz_core probe observed HTTP 500 vs baseline 200',
  impact: 'availability',
  recommended_fix: 'harden parser',
  anomaly_type: 'crash_500',
  payload_class: 'novel',
  novelty_score: 0.84,
  confidence: 0.64,
  fp_routed: false,
  kev_listed: false,
  target_url: 'https://app.acme.test/',
}

function jsonFor(url, opts) {
  const method = (opts?.method || 'GET').toUpperCase()
  if (url.startsWith('/api/discovery-lab/runs') && method === 'POST') {
    return {
      ok: true,
      run_id: 'run-1',
      job_id: 'job-1',
      run: {
        id: 'run-1',
        status: 'queued',
        target_host: 'app.acme.test',
        target_url: 'https://app.acme.test/',
        intensity: 'normal',
        candidates_count: 0,
        probes_sent: 0,
        created_at: '2026-09-10T12:00:00Z',
      },
    }
  }
  if (url === '/api/discovery-lab/runs?limit=40' || url.startsWith('/api/discovery-lab/runs?')) {
    return { runs: [] }
  }
  if (url.startsWith('/api/discovery-lab/runs/run-1')) {
    return {
      id: 'run-1',
      status: 'completed',
      target_host: 'app.acme.test',
      intensity: 'normal',
      candidates_count: 1,
      probes_sent: 8,
    }
  }
  if (url.startsWith('/api/discovery-lab/candidates/cand-1/disclosure') && method === 'POST') {
    return {
      id: 'pack-1',
      candidate_id: 'cand-1',
      status: 'draft',
      title: CANDIDATE.title,
      recipient_kind: 'national_cert',
      technical_summary: CANDIDATE.technical_summary,
    }
  }
  if (url.startsWith('/api/discovery-lab/candidates/cand-1') && method === 'PATCH') {
    return { ...CANDIDATE, status: opts?.body?.action === 'suppress' ? 'suppressed' : 'validated' }
  }
  if (url.startsWith('/api/discovery-lab/candidates/cand-1')) {
    return { ...CANDIDATE, status: 'disclosure_ready' }
  }
  if (url.startsWith('/api/discovery-lab/candidates')) {
    return { candidates: [CANDIDATE] }
  }
  if (url.startsWith('/api/discovery-lab/disclosures')) {
    return { packs: [] }
  }
  return {}
}

describe('DiscoveryLab', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    toast.success.mockReset()
    toast.error.mockReset()
    apiFetch.mockImplementation((url, opts) => Promise.resolve(jsonFor(url, opts)))
  })
  afterEach(cleanup)

  it('loads live Discovery Lab APIs and renders the start control', async () => {
    render(
      <MemoryRouter>
        <DiscoveryLab />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('discovery-lab-page')).toBeInTheDocument()
    expect(screen.getByText('pages.discoveryLab.title')).toBeInTheDocument()
    expect(screen.getByTestId('discovery-lab-start')).toBeInTheDocument()
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith('/api/discovery-lab/runs?limit=40')
      expect(apiFetch).toHaveBeenCalledWith('/api/discovery-lab/candidates?limit=200')
      expect(apiFetch).toHaveBeenCalledWith('/api/discovery-lab/disclosures?limit=80')
    })
    expect(await screen.findByText('Novel parser crash on authorized host')).toBeInTheDocument()
  })

  it('starts a lab run against the authorized client target', async () => {
    render(
      <MemoryRouter>
        <DiscoveryLab />
      </MemoryRouter>,
    )
    await screen.findByTestId('discovery-lab-start')
    fireEvent.click(screen.getByTestId('discovery-lab-start'))
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/discovery-lab/runs',
        expect.objectContaining({
          method: 'POST',
          body: expect.objectContaining({
            client_id: 7,
            target: 'https://app.acme.test',
            intensity: 'normal',
          }),
        }),
      )
    })
  })

  it('validates a candidate then opens a disclosure pack', async () => {
    render(
      <MemoryRouter>
        <DiscoveryLab />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('discovery-validate-cand-1')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('discovery-validate-cand-1'))
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/discovery-lab/candidates/cand-1',
        expect.objectContaining({ method: 'PATCH', body: { action: 'validate' } }),
      )
    })
    expect(await screen.findByTestId('discovery-open-disclosure-cand-1')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('discovery-open-disclosure-cand-1'))
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/discovery-lab/candidates/cand-1/disclosure',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })
})
