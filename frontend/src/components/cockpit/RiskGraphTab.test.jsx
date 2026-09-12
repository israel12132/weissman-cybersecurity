import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import React from 'react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('../../context/ClientContext', () => ({
  useClient: () => ({ selectedClientId: '7' }),
}))
vi.mock('../ui/Button', () => ({
  default: (p) => <button type="button" {...p} />,
}))
vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ nodes, edges }) => (
    <div data-testid="risk-flow" data-nodes={nodes.length} data-edges={edges.length} />
  ),
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  useNodesState: (init) => {
    const [n, set] = React.useState(init)
    return [n, set, vi.fn()]
  },
  useEdgesState: (init) => {
    const [e, set] = React.useState(init)
    return [e, set, vi.fn()]
  },
}))
const apiFetch = vi.fn()
vi.mock('../../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import RiskGraphTab from './RiskGraphTab.jsx'

describe('RiskGraphTab', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('does not paint no-graph theater when the graph API is unavailable', async () => {
    apiFetch.mockResolvedValue({
      ok: false,
      unavailable: true,
      nodes: [],
      edges: [],
      detail: 'store down',
    })
    render(<RiskGraphTab />)
    expect(await screen.findByTestId('risk-graph-unavailable')).toBeTruthy()
    expect(screen.queryByText('components.cockpitTabs.riskGraph.no_graph_data')).toBeNull()
    expect(screen.queryByText('components.cockpitTabs.riskGraph.build_graph')).toBeNull()
  })

  it('wires live from_node_id/to_node_id edges, not undefined source/target', async () => {
    apiFetch.mockResolvedValue({
      nodes: [{ id: 1, label: 'a', node_type: 'asset' }, { id: 2, label: 'b', node_type: 'finding' }],
      edges: [{ from_node_id: 1, to_node_id: 2, edge_type: 'exposes' }],
    })
    render(<RiskGraphTab />)
    const flow = await screen.findByTestId('risk-flow')
    expect(flow.getAttribute('data-nodes')).toBe('2')
    expect(flow.getAttribute('data-edges')).toBe('1')
    expect(screen.queryByTestId('risk-graph-unavailable')).toBeNull()
  })

  it('surfaces a truncated graph instead of a complete inventory', async () => {
    apiFetch.mockResolvedValue({
      nodes: [{ id: 1, label: 'a', node_type: 'asset' }],
      edges: [],
      truncated: true,
    })
    render(<RiskGraphTab />)
    expect(await screen.findByTestId('risk-graph-truncated')).toBeTruthy()
    expect(screen.queryByTestId('risk-graph-unavailable')).toBeNull()
  })
})
