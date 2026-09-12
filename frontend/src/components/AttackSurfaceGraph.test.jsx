import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import React from 'react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))
vi.mock('react-router', () => ({
  useParams: () => ({ clientId: '7' }),
}))
vi.mock('./ui/StandaloneLabShell', () => ({
  default: ({ children, title }) => (
    <div data-testid="asm-shell">
      {title}
      {children}
    </div>
  ),
}))
vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ nodes, edges }) => (
    <div data-testid="asm-flow" data-nodes={nodes.length} data-edges={edges.length} />
  ),
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  MarkerType: { ArrowClosed: 'arrowclosed' },
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
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import AttackSurfaceGraph from './AttackSurfaceGraph.jsx'

describe('AttackSurfaceGraph', () => {
  beforeEach(() => apiFetch.mockReset())
  afterEach(cleanup)

  it('wires live source/target edges from the ASM graph API', async () => {
    apiFetch.mockResolvedValue({
      run_id: 11,
      nodes: [
        { id: 'root', label: 'example.com', node_type: 'root', status: 'ok' },
        { id: 'www', label: 'www.example.com', node_type: 'subdomain', status: 'exposed' },
      ],
      edges: [{ source: 'root', target: 'www', edge_type: 'CNAME' }],
      truncated: false,
    })
    render(<AttackSurfaceGraph />)
    const flow = await screen.findByTestId('asm-flow')
    expect(flow.getAttribute('data-nodes')).toBe('2')
    expect(flow.getAttribute('data-edges')).toBe('1')
    expect(screen.queryByTestId('asm-graph-truncated')).toBeNull()
  })

  it('surfaces a truncated graph instead of a complete inventory', async () => {
    apiFetch.mockResolvedValue({
      run_id: 11,
      nodes: [{ id: 'root', label: 'example.com', node_type: 'root', status: 'ok' }],
      edges: [],
      truncated: true,
    })
    render(<AttackSurfaceGraph />)
    expect(await screen.findByTestId('asm-graph-truncated')).toBeTruthy()
  })
})
