import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, d) => (d && typeof d === 'object' && d.count != null ? `${k}:${d.count}` : k),
    i18n: { language: 'en' },
  }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 1, name: 'Acme', domain: 'acme.test' }],
    selectedClientId: 1,
    setSelectedClientId: vi.fn(),
  }),
}))

vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))

vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled, type = 'button' }) => (
    <button type={type} onClick={onClick} disabled={disabled}>{children}</button>
  ),
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
vi.mock('../components/ui/DataTable', () => ({ __esModule: true, default: () => <div data-testid="choke-table" /> }))
vi.mock('../components/ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title, body }) => (
    <div>
      <p>{title}</p>
      <p>{body}</p>
    </div>
  ),
}))
vi.mock('../components/ui/EvidenceNotice', () => ({ __esModule: true, default: ({ children }) => <p>{children}</p> }))
vi.mock('../components/ui/ExecutiveWidget', () => ({
  __esModule: true,
  default: ({ label, value }) => (
    <div>
      {label}:{value}
    </div>
  ),
}))
vi.mock('../components/ui/Skeleton', () => ({ SkeletonWidgetGrid: () => null }))
vi.mock('../lib/exportFindingsCsv', () => ({ downloadCsv: () => {} }))

import AttackPaths from './AttackPaths.jsx'

describe('AttackPaths crown-jewel panel', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation(async (url) => {
      if (String(url).includes('/risk-graph/nodes/')) {
        return { ok: true }
      }
      if (String(url).includes('/risk-graph')) {
        return {
          nodes: [
            {
              id: 42,
              label: 'db.prod',
              graph_key: 'db',
              node_type: 'host',
              internet_exposed: false,
              crown_jewel: false,
            },
          ],
        }
      }
      if (String(url).includes('/attack-paths/')) {
        return {
          snapshot: {
            entry_count: 1,
            jewel_count: 0,
            choke_points: [],
            paths: [],
            computed_at_unix: 1_700_000_000,
            total_path_ale_usd: 0,
          },
        }
      }
      return {}
    })
  })
  afterEach(cleanup)

  it('lists live graph nodes and PATCHes crown_jewel', async () => {
    render(<AttackPaths />)
    await waitFor(() => expect(screen.getByText('db.prod')).toBeTruthy())
    expect(screen.getByText('pages.attackPaths.jewel_panel')).toBeTruthy()
    expect(screen.getByText('pages.attackPaths.zero_jewel_banner')).toBeTruthy()

    const jewel = screen.getByLabelText('pages.attackPaths.flag_jewel')
    fireEvent.click(jewel)
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/42/flags',
        expect.objectContaining({
          method: 'PATCH',
          body: { crown_jewel: true },
        }),
      )
    })
  })
})
