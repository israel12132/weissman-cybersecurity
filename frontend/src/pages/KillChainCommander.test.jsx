import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => {
      if (d && typeof d === 'object' && d.defaultValue) return d.defaultValue
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
  default: () => <button type="button">refresh</button>,
}))
vi.mock('../components/EngineRealityBadge', () => ({
  __esModule: true,
  default: () => <span>LIVE PROBE</span>,
}))
vi.mock('../components/clients/ScopedClientControl', () => ({
  __esModule: true,
  default: () => <label>client</label>,
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    selectedClientId: 1,
    setSelectedClientId: vi.fn(),
    clients: [{ id: 1, name: 'Example' }],
  }),
}))

import KillChainCommander from './KillChainCommander.jsx'

describe('KillChainCommander', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('shows fail-closed empty corpus from live API empty_reason', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      live: true,
      client_id: 1,
      client_name: 'Example',
      stages: [],
      empty_reason: 'no persisted findings — Commander will not fabricate an APT path',
      findings_considered: 0,
      micro_severity_points: 0,
    })
    render(
      <MemoryRouter>
        <KillChainCommander />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText(/no persisted findings/i)).toBeTruthy()
    })
    expect(apiFetch).toHaveBeenCalledWith('/api/kill-chain-commander?client_id=1')
  })

  it('renders live-shaped stages from persisted findings', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      live: true,
      client_id: 1,
      client_name: 'Example',
      findings_considered: 1,
      micro_severity_points: 12,
      fair_ale_usd: 250000,
      stages: [
        {
          stage: 'recon',
          label: 'Recon',
          finding_count: 1,
          findings: [{ title: 'Open OSINT port', severity: 'high', engine_id: 'asm', mitre: 'T1595' }],
        },
        { stage: 'foothold', label: 'Foothold', finding_count: 0, findings: [] },
        { stage: 'identity', label: 'Identity', finding_count: 0, findings: [] },
        { stage: 'privilege', label: 'Privilege', finding_count: 0, findings: [] },
        { stage: 'impact', label: 'Impact', finding_count: 0, findings: [] },
      ],
    })
    render(
      <MemoryRouter>
        <KillChainCommander />
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('Open OSINT port')).toBeTruthy()
    })
    expect(screen.getByText('T1595')).toBeTruthy()
    expect(screen.getAllByText('$250.0K').length).toBeGreaterThan(0)
  })
})
