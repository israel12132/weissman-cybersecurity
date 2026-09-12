import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { snapshotHasNoJewels, graphNodesFromPayload } from './AttackPaths.jsx'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
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
vi.mock('../components/ui/DataTable', () => ({ __esModule: true, default: () => null }))
vi.mock('../components/ui/ExecutiveWidget', () => ({
  __esModule: true,
  default: ({ label, value }) => <div>{label}:{String(value)}</div>,
}))
vi.mock('../components/ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title }) => <div>{title}</div>,
}))
vi.mock('../components/ui/EvidenceNotice', () => ({ __esModule: true, default: ({ children }) => <div>{children}</div> }))
vi.mock('../components/ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled, ...rest }) => (
    <button type="button" onClick={onClick} disabled={disabled} {...rest}>{children}</button>
  ),
}))
vi.mock('../components/ui/Toaster', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))
vi.mock('../context/ClientContext', () => ({
  useClient: () => ({
    clients: [{ id: 7, name: 'Lab' }],
    selectedClientId: 7,
    setSelectedClientId: () => {},
  }),
}))

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({ apiFetch: (...args) => apiFetch(...args) }))

import AttackPaths from './AttackPaths.jsx'

describe('attack-path helpers', () => {
  it('detects a zero-jewel snapshot', () => {
    expect(snapshotHasNoJewels({ jewel_count: 0 })).toBe(true)
    expect(snapshotHasNoJewels({ jewel_count: 2 })).toBe(false)
  })

  it('reads nodes from a graph payload', () => {
    expect(graphNodesFromPayload({ nodes: [{ id: 1 }] })).toHaveLength(1)
    expect(graphNodesFromPayload(null)).toEqual([])
  })
})

describe('AttackPaths crown-jewel board', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    apiFetch.mockImplementation(async (url) => {
      if (String(url).includes('/risk-graph') && !String(url).includes('/flags')) {
        return { nodes: [{ id: 11, label: 'HR-DB', node_type: 'datastore', crown_jewel: false }] }
      }
      if (String(url).includes('/attack-paths')) {
        return { snapshot: { jewel_count: 0, entry_count: 1, paths: [], choke_points: [], computed_at_unix: 0 } }
      }
      return { ok: true }
    })
  })
  afterEach(cleanup)

  it('lets an operator flag a live graph node as a crown jewel', async () => {
    render(<AttackPaths />)
    const btn = await screen.findByTestId('crown-jewel-11')
    expect(btn.textContent).toContain('pages.attackPaths.jewel_off')
    fireEvent.click(btn)
    await waitFor(() => {
      expect(apiFetch).toHaveBeenCalledWith(
        '/api/risk-graph/nodes/11/flags',
        expect.objectContaining({ method: 'PATCH', body: { crown_jewel: true } }),
      )
    })
  })
})
