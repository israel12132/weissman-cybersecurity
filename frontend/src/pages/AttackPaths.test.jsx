import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
  initReactI18next: { type: '3rdParty', init: () => {} },
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 7, name: 'Acme', domain: 'acme.test' }],
    selectedClientId: 7,
    setSelectedClientId: vi.fn(),
  }),
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
vi.mock('../components/ui/DataTable', () => ({
  __esModule: true,
  default: () => null,
}))

import AttackPaths from './AttackPaths.jsx'

describe('AttackPaths', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation(async (url, opts = {}) => {
      if (String(url).includes('/risk-graph') && !String(url).includes('/flags')) {
        return {
          nodes: [
            {
              id: 11,
              label: 'payroll-db',
              graph_key: 'db:payroll',
              node_type: 'identity',
              crown_jewel: false,
              internet_exposed: true,
              risk_score: 88,
            },
          ],
        }
      }
      if (String(url).includes('/flags')) {
        return { ok: true, id: 11, client_id: 7, method: opts.method }
      }
      return {
        ok: true,
        snapshot: {
          entry_count: 1,
          jewel_count: 0,
          paths: [],
          choke_points: [],
          computed_at_unix: 1_700_000_000,
        },
      }
    })
  })
  afterEach(cleanup)

  it('loads live attack paths and the risk-graph jewel inventory', async () => {
    render(<AttackPaths />)
    expect(await screen.findByTestId('crown-jewel-panel')).toBeInTheDocument()
    expect(screen.getByText('payroll-db')).toBeInTheDocument()
    expect(screen.getByTestId('zero-jewel-banner')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledWith('/api/attack-paths/7')
    expect(apiFetch).toHaveBeenCalledWith('/api/clients/7/risk-graph')
  })

  it('PATCHes crown_jewel then recomputes paths', async () => {
    render(<AttackPaths />)
    const toggle = await screen.findByTestId('crown-jewel-toggle-11')
    fireEvent.click(toggle)
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/11/flags',
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
})
