import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

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
  default: ({ title, actions, children }) => (
    <div>
      <h1>{title}</h1>
      <div>{actions}</div>
      {children}
    </div>
  ),
}))
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/DataTable', () => ({
  __esModule: true,
  default: ({ data }) => (
    <div data-testid="lanes-table">{(data || []).map((r) => r.title).join(' ')}</div>
  ),
}))

import CompetitiveWinRoom, { winRoomRows } from './CompetitiveWinRoom.jsx'

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CompetitiveWinRoom />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('CompetitiveWinRoom', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('renders live market-readiness from GET /api/market-readiness', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      thesis: 'Weissman finds; Palo Alto blocks.',
      engines_total: 586,
      prevention_fabric_engines: ['prevention_fabric_breach_proof', 'ngfw_posture'],
      honest_gaps: [
        { id: 'scim', severity: 'procurement', detail: 'No SCIM 2.0' },
      ],
      live_findings: [{ source: 'ngfw_posture', count: 2 }],
      moat: {
        lanes_covered: 1,
        lanes_total: 1,
        lanes: [
          { id: 'prevention_fabric', title: 'Prevention-fabric breach proof', live_engine_count: 7, beats: 'Palo Alto' },
        ],
      },
    })
    renderPage()
    expect(await screen.findByTestId('win-room-thesis')).toHaveTextContent('Weissman finds; Palo Alto blocks.')
    expect(screen.getByTestId('win-room-gap')).toHaveTextContent('No SCIM 2.0')
    expect(screen.getByTestId('lanes-table')).toHaveTextContent('Prevention-fabric breach proof')
    expect(apiFetch).toHaveBeenCalledWith('/api/market-readiness')
  })

  it('surfaces live_findings_error instead of a fake zero count', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      thesis: 'Weissman finds; Palo Alto blocks.',
      engines_total: 586,
      prevention_fabric_engines: [],
      honest_gaps: [],
      live_findings: null,
      live_findings_error: 'database unavailable',
      moat: { lanes_covered: 0, lanes_total: 1, lanes: [] },
    })
    renderPage()
    expect(await screen.findByText('pages.competitiveWinRoom.findings_unavailable')).toBeTruthy()
    expect(screen.getByText('database unavailable')).toBeTruthy()
    expect(screen.getByText('pages.competitiveWinRoom.findings_unknown')).toBeTruthy()
  })

  it('shows load_failed when GET /api/market-readiness rejects', async () => {
    apiFetch.mockRejectedValue(new Error('401 unauthorized'))
    renderPage()
    expect(await screen.findByText('pages.competitiveWinRoom.load_failed')).toBeTruthy()
    expect(screen.getByText('401 unauthorized')).toBeTruthy()
  })

  it('flattens gaps, lanes, and live findings for CSV', () => {
    const rows = winRoomRows({
      honest_gaps: [{ id: 'scim', severity: 'procurement', detail: 'missing' }],
      moat: { lanes: [{ id: 'ot_ics', title: 'OT', beats: 'Claroty', live_engine_count: 4 }] },
      live_findings: [{ source: 'ngfw_posture', count: 3 }],
    })
    expect(rows).toEqual([
      ['gap', 'scim', 'procurement', 'missing', ''],
      ['lane', 'ot_ics', 'OT', 'Claroty', '4'],
      ['finding', 'ngfw_posture', '', '', '3'],
    ])
  })
})
