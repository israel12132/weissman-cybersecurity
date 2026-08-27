import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (k === 'pages.killChainCommander.formula_line' && d && typeof d === 'object') {
        return `${d.sev}×${d.crit}×${d.exp} (${d.expLabel})`
      }
      if (k === 'pages.killChainCommander.kpi_residual_hint' && d && typeof d === 'object') {
        return `${d.pct}%`
      }
      if (k === 'pages.killChainCommander.kpi_findings_hint' && d && typeof d === 'object') {
        return `of ${d.n}`
      }
      if (k === 'pages.killChainCommander.domain_hint' && d && typeof d === 'object') {
        return d.domain
      }
      if (k === 'pages.killChainCommander.kpi_fair_hint_priced' && d && typeof d === 'object') {
        return `SLE ${d.sle}`
      }
      if (typeof d === 'string') return d
      if (d && typeof d === 'object' && d.defaultValue) return d.defaultValue
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
vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: ({ onRefresh, onExport }) => (
    <div>
      <button type="button" onClick={onRefresh}>refresh</button>
      <button type="button" onClick={onExport}>export</button>
    </div>
  ),
}))
vi.mock('../components/EngineRealityBadge', () => ({
  __esModule: true,
  default: () => <span>LIVE PROBE</span>,
}))

const clientState = {
  selectedClientId: 1,
  setSelectedClientId: vi.fn(),
  clients: [{ id: 1, name: 'Example', domains: '["example.com"]' }],
}
vi.mock('../context/ClientContext', () => ({
  useClient: () => clientState,
}))

const authState = { session: { ok: true, role: 'ceo', is_owner: true } }
vi.mock('../context/AuthContext', () => ({
  useAuthOptional: () => authState,
}))

import KillChainCommander from './KillChainCommander.jsx'

const emptySnap = {
  ok: true,
  live: true,
  client_id: 1,
  client_name: 'Example',
  primary_domain: 'example.com',
  stages: [
    { stage: 'recon', label: 'Reconnaissance', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'foothold', label: 'Foothold', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'identity', label: 'Identity', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'privilege', label: 'Privilege', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'impact', label: 'Impact', mitre_tactics: [], finding_count: 0, findings: [] },
  ],
  edges: [],
  pricing: {
    formula: {
      name: 'Micro-Severity (SOC analyst local ranking)',
      expression: 'severity_weight × asset_criticality × exposure',
      severity_weights: { critical: 5 },
      exposure: { internet_facing: 2 },
      usd_overlay: 'Not residual financial risk. Not a USD blast-radius.',
    },
    total_risk_points: 0,
    residual_if_top3_fixed: 0,
    residual_reduction_pct: 0,
    top3_fixes: [],
    total_priced_usd: null,
    fair: {
      method: 'fair_usd_blast_radius',
      priced: false,
      cannot_price_reason: 'Cannot price — no FAIR blast-radius snapshot (asset valuations / risk graph missing). Weissman will not invent a dollar figure.',
    },
  },
  jobs: [],
  honesty: { live_evidence_only: true, no_fabricated_apt: true, fail_closed_empty: true, client_bound: true, formula_published: true },
  empty_reason: 'No live findings for this customer. Run engines against the assigned domain, then return — Weissman will not fabricate a kill chain.',
  findings_considered: 0,
  headline_risk: {
    method: 'fair_usd_blast_radius',
    priced: false,
    cannot_price_reason: 'Cannot price — no FAIR blast-radius snapshot (asset valuations / risk graph missing). Weissman will not invent a dollar figure.',
  },
}

const liveSnap = {
  ...emptySnap,
  empty_reason: null,
  findings_considered: 2,
  stages: [
    {
      stage: 'recon',
      label: 'Reconnaissance',
      mitre_tactics: ['Reconnaissance'],
      finding_count: 1,
      findings: [{
        id: 1,
        finding_id: 'F-1',
        title: 'Public subdomain www.example.com enumerated',
        severity: 'medium',
        source: 'osint',
        confidence: 0.8,
        risk_points: 6,
        proof_snippet: 'DNS A record',
        mitre: [{ id: 'T1595', name: 'Active Scanning', source: 'finding_raw_data' }],
        formula_inputs: { severity_weight: 3, asset_criticality: 1, exposure_weight: 2, exposure: 'internet_facing' },
      }],
    },
    {
      stage: 'foothold',
      label: 'Foothold',
      mitre_tactics: ['Initial Access'],
      finding_count: 1,
      findings: [{
        id: 2,
        finding_id: 'F-2',
        title: 'Unauthenticated SQL injection on /login',
        severity: 'critical',
        source: 'sqli_engine',
        confidence: 0.92,
        risk_points: 25,
        proof_snippet: 'HTTP 200 from boolean-based probe',
        mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application', source: 'finding_raw_data' }],
        formula_inputs: { severity_weight: 5, asset_criticality: 2.5, exposure_weight: 2, exposure: 'internet_facing' },
      }],
    },
    { stage: 'identity', label: 'Identity', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'privilege', label: 'Privilege', mitre_tactics: [], finding_count: 0, findings: [] },
    { stage: 'impact', label: 'Impact', mitre_tactics: [], finding_count: 0, findings: [] },
  ],
  pricing: {
    ...emptySnap.pricing,
    total_risk_points: 31,
    residual_if_top3_fixed: 0,
    residual_reduction_pct: 100,
    top3_fixes: [
      { id: 2, finding_id: 'F-2', title: 'Unauthenticated SQL injection on /login', stage: 'foothold', risk_points: 25 },
    ],
    total_priced_usd: 88200,
    fair: {
      method: 'fair_usd_blast_radius',
      priced: true,
      ale_annualised_usd: 88200,
      sle_worst_usd: 245000,
      cannot_price_reason: null,
    },
  },
  headline_risk: {
    method: 'fair_usd_blast_radius',
    priced: true,
    ale_annualised_usd: 88200,
    sle_worst_usd: 245000,
    cannot_price_reason: null,
  },
}

describe('KillChainCommander', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    clientState.selectedClientId = 1
    clientState.clients = [{ id: 1, name: 'Example', domains: '["example.com"]' }]
    authState.session = { ok: true, role: 'ceo', is_owner: true }
  })
  afterEach(cleanup)

  it('shows fail-closed empty corpus from live API empty_reason', async () => {
    apiFetch.mockResolvedValue(emptySnap)
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => {
      expect(screen.getByText(/will not fabricate a kill chain/i)).toBeTruthy()
    })
    expect(apiFetch).toHaveBeenCalledWith('/api/kill-chain-commander?client_id=1')
    expect(screen.queryByText(/APT29|Lazarus|coming soon/i)).toBeNull()
  })

  it('renders live-shaped graph nodes with MITRE and formula', async () => {
    apiFetch.mockResolvedValue(liveSnap)
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => {
      expect(screen.getAllByText(/Unauthenticated SQL injection/i).length).toBeGreaterThan(0)
    })
    expect(screen.getAllByText(/Public subdomain www.example.com/i).length).toBeGreaterThan(0)
    expect(screen.getByText('T1190')).toBeTruthy()
    expect(screen.getAllByText('severity_weight × asset_criticality × exposure').length).toBeGreaterThan(0)
    expect(screen.getByText('pages.killChainCommander.micro_formula_title')).toBeTruthy()
    expect(screen.getAllByText('$88.2K').length).toBeGreaterThan(0)
    expect(screen.getByTestId('kill-chain-fair-headline').textContent).toBe('$88.2K')
    expect(screen.queryByText('$31')).toBeNull()
  })

  it('CEO headline is FAIR ALE, never the Micro-Severity product', async () => {
    apiFetch.mockResolvedValue(liveSnap)
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => {
      expect(screen.getByTestId('kill-chain-fair-headline').textContent).toBe('$88.2K')
    })
    expect(screen.getByText('pages.killChainCommander.kpi_fair')).toBeTruthy()
    expect(screen.getByText('pages.killChainCommander.kpi_micro')).toBeTruthy()
    expect(screen.getByText('31.0')).toBeTruthy()
  })

  it('fail-visible cannot-price when FAIR inputs are missing', async () => {
    apiFetch.mockResolvedValue(emptySnap)
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => {
      expect(screen.getByTestId('kill-chain-fair-headline').textContent).toMatch(/cannot_price/i)
    })
    expect(screen.queryByText(/\$88/)).toBeNull()
    expect(screen.getAllByText(/will not invent a dollar figure/i).length).toBeGreaterThan(0)
  })

  it('hides the client picker for assigned-client-only sessions', async () => {
    authState.session = {
      ok: true,
      role: 'client',
      assigned_client_id: 1,
      is_client_user: true,
      client_picker_hidden: true,
      allowed_client_ids: [1],
    }
    apiFetch.mockResolvedValue(liveSnap)
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => {
      expect(screen.getAllByText(/Unauthenticated SQL injection/i).length).toBeGreaterThan(0)
    })
    expect(screen.queryByRole('combobox')).toBeNull()
  })

  it('surfaces compose 409 empty_reason without inventing a chain', async () => {
    apiFetch.mockImplementation(async (_url, opts = {}) => {
      if (String(opts.method || 'GET').toUpperCase() === 'POST') {
        const err = new Error('No live findings')
        err.status = 409
        err.response = {
          json: async () => ({
            ok: false,
            error_code: 'kill_chain_corpus_empty',
            empty_reason: 'No live findings for this customer.',
          }),
        }
        throw err
      }
      return emptySnap
    })
    render(<MemoryRouter><KillChainCommander /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText(/will not fabricate/i)).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'pages.killChainCommander.compose' }))
    await waitFor(() => {
      expect(screen.getByRole('alert').textContent).toMatch(/No live findings/)
    })
  })
})
