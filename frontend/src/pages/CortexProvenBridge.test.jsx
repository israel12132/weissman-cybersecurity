import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (d && typeof d === 'object' && 'n' in d) return `${k}:${d.n}`
      return typeof d === 'string' ? d : k
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
  default: ({ onRefresh }) => (
    <button type="button" onClick={onRefresh}>refresh</button>
  ),
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: 7, clients: [{ id: 7, name: 'acme' }] }),
}))

import CortexProvenBridge from './CortexProvenBridge.jsx'

describe('CortexProvenBridge', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('loads the live scan→finding map and shows a proven XSIAM blind spot', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      cortex_configured: true,
      cortex_mode: 'Xsiam',
      counts: {
        mapped: 1,
        proven_eligible: 1,
        already_pushed: 0,
        xdr_blind_spots: 1,
        xdr_already_had: 0,
      },
      items: [{
        id: 42,
        finding_id: 'ssrf-1',
        title: 'SSRF via webhook',
        severity: 'high',
        engine_id: 'ssrf_advanced',
        source: 'ssrf_advanced',
        proof_kind: 'oast_callback',
        eligible: true,
        cortex_status: 'blind_spot',
        xdr_had_matching_alert: false,
        report_run_id: 9,
        target: 'https://api.acme.test',
      }],
    })
    render(
      <MemoryRouter>
        <CortexProvenBridge />
      </MemoryRouter>,
    )
    expect(await screen.findByText('SSRF via webhook')).toBeInTheDocument()
    expect(screen.getByText('pages.cortexProvenBridge.blind_spot')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/findings/scan-cortex-bridge?client_id=7'),
    )
  })

  it('shows a visible missing-Cortex state instead of fake coverage', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      cortex_configured: false,
      note: 'Cortex XSIAM/XSOAR is not configured',
      counts: { mapped: 0, proven_eligible: 0, already_pushed: 0, xdr_blind_spots: 0, xdr_already_had: 0 },
      items: [],
    })
    render(
      <MemoryRouter>
        <CortexProvenBridge />
      </MemoryRouter>,
    )
    expect(await screen.findByText('pages.cortexProvenBridge.empty_title')).toBeInTheDocument()
    expect(screen.getByText('pages.cortexProvenBridge.missing')).toBeInTheDocument()
    expect(screen.getByText('pages.cortexProvenBridge.open_integrations')).toBeInTheDocument()
  })

  it('flushes proven findings through the live batch API', async () => {
    apiFetch
      .mockResolvedValueOnce({
        ok: true,
        cortex_configured: true,
        counts: { mapped: 1, proven_eligible: 1, already_pushed: 0, xdr_blind_spots: 0, xdr_already_had: 0 },
        items: [{ id: 1, title: 'Open Redis', severity: 'high', engine_id: 'redis_security', eligible: true, cortex_status: 'mapped' }],
      })
      .mockResolvedValueOnce({ ok: true, pushed: 1, skipped: 0 })
      .mockResolvedValueOnce({
        ok: true,
        cortex_configured: true,
        counts: { mapped: 1, proven_eligible: 1, already_pushed: 1, xdr_blind_spots: 0, xdr_already_had: 0 },
        items: [{ id: 1, title: 'Open Redis', severity: 'high', engine_id: 'redis_security', eligible: true, cortex_status: 'pushed' }],
      })
    render(
      <MemoryRouter>
        <CortexProvenBridge />
      </MemoryRouter>,
    )
    expect(await screen.findByText('Open Redis')).toBeInTheDocument()
    fireEvent.click(screen.getByText('pages.cortexProvenBridge.flush'))
    expect(await screen.findByText('pages.cortexProvenBridge.flush_ok:1')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/findings/scan-cortex-bridge/flush', expect.objectContaining({
      method: 'POST',
    }))
  })
})
