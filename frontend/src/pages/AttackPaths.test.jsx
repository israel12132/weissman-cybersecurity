import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { needsCrownJewelSeed, rankJewelCandidates } from './AttackPaths.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
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
    setSelectedClientId: () => {},
  }),
}))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
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
vi.mock('../components/ui/DataTable', () => ({ __esModule: true, default: () => null }))

import AttackPaths from './AttackPaths.jsx'

describe('needsCrownJewelSeed', () => {
  it('is false without a snapshot', () => {
    expect(needsCrownJewelSeed(null)).toBe(false)
    expect(needsCrownJewelSeed(undefined)).toBe(false)
  })

  it('is true only when jewel_count is zero', () => {
    expect(needsCrownJewelSeed({ jewel_count: 0 })).toBe(true)
    expect(needsCrownJewelSeed({ jewel_count: '0' })).toBe(true)
    expect(needsCrownJewelSeed({ jewel_count: 3 })).toBe(false)
  })
})

describe('rankJewelCandidates', () => {
  it('drops honeypots and ranks jewels then risk', () => {
    const ranked = rankJewelCandidates([
      { id: 1, honey_node: true, risk_score: 99, label: 'honey' },
      { id: 2, crown_jewel: false, internet_exposed: true, risk_score: 10, label: 'entry' },
      { id: 3, crown_jewel: true, risk_score: 1, label: 'jewel' },
      { id: 4, crown_jewel: false, risk_score: 80, label: 'hot' },
    ])
    expect(ranked.map((n) => n.id)).toEqual([3, 2, 4])
  })
})

describe('AttackPaths jewel toggle', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation((url, opts = {}) => {
      if (String(url).includes('/risk-graph/nodes/')) {
        return Promise.resolve({ ok: true, id: 3 })
      }
      if (String(url).includes('/risk-graph')) {
        return Promise.resolve({
          nodes: [{ id: 3, label: 'db-prod', node_type: 'identity', risk_score: 88, crown_jewel: false }],
          edges: [],
        })
      }
      if (opts.method === 'POST') {
        return Promise.resolve({ ok: true, snapshot: { jewel_count: 1, paths: [], choke_points: [] } })
      }
      return Promise.resolve({
        snapshot: { jewel_count: 0, entry_count: 1, paths: [], choke_points: [], computed_at_unix: 1 },
      })
    })
  })
  afterEach(cleanup)

  it('PATCHes crown_jewel then recomputes', async () => {
    render(
      <MemoryRouter>
        <AttackPaths />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('jewel-seed-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-jewel-3'))
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/3/flags',
        expect.objectContaining({ method: 'PATCH', body: { crown_jewel: true } }),
      )
    })
  })
})
