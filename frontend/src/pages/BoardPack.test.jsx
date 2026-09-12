import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k) => k,
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 7, name: 'Acme' }],
    selectedClientId: 7,
    setSelectedClientId: vi.fn(),
  }),
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
vi.mock('../components/engine/ShellScanActions', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))

import BoardPack from './BoardPack.jsx'

describe('BoardPack', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockResolvedValue({
      ok: true,
      kpis: {
        bod_p0: 2,
        kev_listed: 3,
        ale_usd: 120000,
        attack_paths: 4,
      },
      fair_note: 'Live FAIR snapshot',
      paths_message: 'Live Dijkstra snapshot',
      first_mover_message: 'No first-mover snapshot yet',
      top_techniques: [
        { technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', count: 5, critical: 2 },
      ],
      p0_findings: [{ id: 1, severity: 'critical', title: 'Exposed admin', cve: 'CVE-2024-0001' }],
    })
  })
  afterEach(() => cleanup())

  it('loads live KPIs and TTP rows from the board-pack API', async () => {
    render(
      <MemoryRouter>
        <BoardPack />
      </MemoryRouter>,
    )
    await waitFor(() => expect(apiFetch).toHaveBeenCalled())
    expect(apiFetch.mock.calls[0][0]).toContain('/api/clients/7/board-pack')
    expect(await screen.findByText('T1190')).toBeTruthy()
    expect(screen.getByText('pages.boardPack.p0_banner')).toBeTruthy()
  })
})
