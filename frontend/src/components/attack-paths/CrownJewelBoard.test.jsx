import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import CrownJewelBoard, {
  snapshotHasNoJewels,
  graphNodesFromPayload,
  patchCrownJewelFlag,
} from './CrownJewelBoard.jsx'

vi.mock('../ui/EmptyState', () => ({
  __esModule: true,
  default: ({ title }) => <div>{title}</div>,
}))
vi.mock('../ui/Button', () => ({
  __esModule: true,
  default: ({ children, onClick, disabled, ...rest }) => (
    <button type="button" onClick={onClick} disabled={disabled} {...rest}>{children}</button>
  ),
}))

const t = (k) => k

describe('crown-jewel helpers', () => {
  it('detects a zero-jewel snapshot', () => {
    expect(snapshotHasNoJewels({ jewel_count: 0 })).toBe(true)
    expect(snapshotHasNoJewels({ jewel_count: 2 })).toBe(false)
  })

  it('reads nodes from a graph payload', () => {
    expect(graphNodesFromPayload({ nodes: [{ id: 1 }] })).toHaveLength(1)
    expect(graphNodesFromPayload([{ id: 2 }])).toHaveLength(1)
    expect(graphNodesFromPayload(null)).toEqual([])
  })

  it('PATCHes the live flags endpoint', async () => {
    const apiFetch = vi.fn().mockResolvedValue({ ok: true })
    await patchCrownJewelFlag(apiFetch, { id: 11, crown_jewel: false })
    expect(apiFetch).toHaveBeenCalledWith(
      '/api/risk-graph/nodes/11/flags',
      expect.objectContaining({ method: 'PATCH', body: { crown_jewel: true } }),
    )
  })

  it('refuses to PATCH a node without an id', async () => {
    const apiFetch = vi.fn()
    await expect(patchCrownJewelFlag(apiFetch, {})).rejects.toThrow(/missing graph node id/)
    expect(apiFetch).not.toHaveBeenCalled()
  })
})

describe('CrownJewelBoard', () => {
  afterEach(cleanup)

  it('lets an operator flag a live graph node as a crown jewel', () => {
    const onToggle = vi.fn()
    render(
      <CrownJewelBoard
        nodes={[{ id: 11, label: 'HR-DB', node_type: 'datastore', crown_jewel: false }]}
        busyId={null}
        onToggle={onToggle}
        t={t}
      />,
    )
    const btn = screen.getByTestId('crown-jewel-11')
    expect(btn.textContent).toContain('pages.attackPaths.jewel_off')
    fireEvent.click(btn)
    expect(onToggle).toHaveBeenCalledWith(expect.objectContaining({ id: 11, crown_jewel: false }))
  })

  it('shows an empty graph state when the client has no nodes', () => {
    render(<CrownJewelBoard nodes={[]} busyId={null} onToggle={() => {}} t={t} />)
    expect(screen.getByText('pages.attackPaths.no_graph_title')).toBeTruthy()
  })
})
