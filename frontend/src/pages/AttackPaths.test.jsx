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
  default: () => <div data-testid="data-table" />,
}))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 7, name: 'Acme', domain: 'acme.test' }],
    selectedClientId: 7,
    setSelectedClientId: vi.fn(),
  }),
}))

import AttackPaths from './AttackPaths.jsx'

const ZERO_JEWEL = {
  ok: true,
  zero_jewel: true,
  candidate_jewels: [
    {
      id: 42,
      label: 'prod-vault',
      graph_key: 'identity:vault',
      node_type: 'identity',
      business_value_usd: 250000,
      crown_jewel: false,
    },
  ],
  snapshot: {
    jewel_count: 0,
    entry_count: 1,
    choke_points: [],
    paths: [],
    computed_at_unix: 1_700_000_000,
  },
}

describe('AttackPaths', () => {
  beforeEach(() => {
    apiFetch.mockReset()
  })
  afterEach(cleanup)

  it('shows the zero-jewel banner and marks a candidate via PATCH flags', async () => {
    apiFetch.mockImplementation(async (url) => {
      if (String(url).includes('/flags')) {
        return { ok: true, id: 42, client_id: 7 }
      }
      if (String(url).includes('recompute=1')) {
        return {
          ok: true,
          zero_jewel: false,
          candidate_jewels: [],
          snapshot: { ...ZERO_JEWEL.snapshot, jewel_count: 1 },
        }
      }
      return ZERO_JEWEL
    })

    render(
      <MemoryRouter>
        <AttackPaths />
      </MemoryRouter>,
    )

    expect(await screen.findByTestId('zero-jewel-banner')).toBeInTheDocument()
    expect(screen.getByText('prod-vault')).toBeInTheDocument()
    expect(screen.getByText('pages.attackPaths.zero_jewel_title')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'pages.attackPaths.mark_jewel' }))

    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/42/flags',
        expect.objectContaining({
          method: 'PATCH',
          body: { crown_jewel: true },
        }),
      )
    })
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith('/api/attack-paths/7?recompute=1&top_k=15')
    })
  })

  it('does not show the banner when the snapshot already has crown jewels', async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      zero_jewel: false,
      candidate_jewels: [],
      snapshot: {
        jewel_count: 2,
        entry_count: 1,
        choke_points: [],
        paths: [{ entry: 1, jewel: 2, hops: 2, risk: 8, path_score: 90, steps: [] }],
      },
    })
    render(
      <MemoryRouter>
        <AttackPaths />
      </MemoryRouter>,
    )
    expect(await screen.findByText('pages.attackPaths.top_paths')).toBeInTheDocument()
    expect(screen.queryByTestId('zero-jewel-banner')).not.toBeInTheDocument()
  })
})
