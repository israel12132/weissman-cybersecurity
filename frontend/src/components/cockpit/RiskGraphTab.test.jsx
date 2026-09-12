import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

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
  ReactFlow: () => null,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  useNodesState: () => [[], vi.fn(), vi.fn()],
  useEdgesState: () => [[], vi.fn(), vi.fn()],
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
})
