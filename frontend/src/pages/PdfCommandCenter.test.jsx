import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (k === 'pages.pdfCommandCenter.kpi_fair_hint' && d && typeof d === 'object') {
        return `SLE ${d.sle}`
      }
      if (typeof d === 'string') return d
      if (d && typeof d === 'object' && d.defaultValue) return d.defaultValue
      return k
    },
    i18n: { language: 'en' },
  }),
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
vi.mock('../components/engine/ShellScanActions', () => ({
  __esModule: true,
  default: () => <div>actions</div>,
}))

const clientState = {
  selectedClientId: 1,
  setSelectedClientId: vi.fn(),
  clients: [{ id: 1, name: 'Acme' }],
}
vi.mock('../context/ClientContext', () => ({
  useClient: () => clientState,
}))
vi.mock('../context/AuthContext', () => ({
  useAuthOptional: () => ({ session: { ok: true, role: 'ceo', is_owner: true } }),
}))

import PdfCommandCenter from './PdfCommandCenter.jsx'

const pricedSnap = {
  ok: true,
  live: true,
  client_id: 1,
  client_name: 'Acme',
  corpus: [{ id: 'run:1', kind: 'report_run', title: 'Run 1', finding_count: 3 }],
  findings: { total: 3, critical: 1, high: 1, medium: 1, low: 0 },
  frameworks: [],
  section_catalog: [],
  fair: {
    method: 'fair_usd_blast_radius',
    priced: true,
    ale_annualised_usd: 180_000,
    sle_worst_usd: 98_000,
  },
  headline_risk: {
    method: 'fair_usd_blast_radius',
    priced: true,
    ale_annualised_usd: 180_000,
    sle_worst_usd: 98_000,
  },
  scoring: {
    method: 'fair_usd_blast_radius',
    fair: { priced: true, ale_annualised_usd: 180_000 },
    micro_severity: { method: 'micro_severity_product', not_residual_financial_risk: true },
  },
}

describe('PdfCommandCenter FAIR headline', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    clientState.selectedClientId = 1
  })
  afterEach(cleanup)

  it('uses FAIR ALE as the executive number, not Micro-Severity', async () => {
    apiFetch.mockResolvedValue(pricedSnap)
    render(
      <MemoryRouter>
        <PdfCommandCenter />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('$180.0K')).toBeTruthy()
    })
    expect(apiFetch).toHaveBeenCalledWith('/api/pdf-intelligence?client_id=1')
    expect(screen.getByText('pages.pdfCommandCenter.kpi_fair')).toBeTruthy()
    expect(screen.getByText('pages.pdfCommandCenter.micro_severity_note')).toBeTruthy()
    expect(screen.queryByText('$25')).toBeNull()
  })

  it('fail-visible cannot-price when FAIR inputs are missing', async () => {
    apiFetch.mockResolvedValue({
      ...pricedSnap,
      fair: {
        method: 'fair_usd_blast_radius',
        priced: false,
        cannot_price_reason: 'Cannot price — FAIR inputs missing',
        ale_annualised_usd: null,
      },
      headline_risk: {
        method: 'fair_usd_blast_radius',
        priced: false,
        cannot_price_reason: 'Cannot price — FAIR inputs missing',
        ale_annualised_usd: null,
      },
    })
    render(
      <MemoryRouter>
        <PdfCommandCenter />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('pages.pdfCommandCenter.cannot_price')).toBeTruthy()
    })
    expect(screen.queryByText('$180.0K')).toBeNull()
    expect(screen.getByText(/Cannot price — FAIR inputs missing/)).toBeTruthy()
  })
})
