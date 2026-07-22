import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { ThemeProvider } from '../context/ThemeContext'

// Stub @xyflow so the real ReactFlow doesn't need a WebGL/layout environment.
vi.mock('@xyflow/react', async () => {
  const React = await import('react')
  return {
    ReactFlow: ({ nodes }) => <div data-testid="reactflow">{(nodes || []).length} nodes</div>,
    ReactFlowProvider: ({ children }) => <>{children}</>,
    Background: () => null,
    Controls: () => null,
    Handle: () => null,
    Position: { Top: 'top', Bottom: 'bottom' },
    MarkerType: { ArrowClosed: 'arrowclosed' },
    addEdge: (edge, eds) => [...eds, edge],
    useNodesState: (init) => {
      const [s, set] = React.useState(init)
      return [s, set, () => {}]
    },
    useEdgesState: (init) => {
      const [s, set] = React.useState(init)
      return [s, set, () => {}]
    },
  }
})

import AdvancedShowcase from './AdvancedShowcase.jsx'

afterEach(cleanup)

describe('AdvancedShowcase', () => {
  it('mounts and renders the advanced sections', () => {
    render(
      <ThemeProvider>
        <AdvancedShowcase />
      </ThemeProvider>,
    )
    expect(screen.getByRole('heading', { name: 'Advanced Components' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'AI Command Console' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'SOAR playbook builder' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Partner Portal (MSSP)' })).toBeInTheDocument()
  })

  it('filters the table-of-contents nav', () => {
    render(
      <ThemeProvider>
        <AdvancedShowcase />
      </ThemeProvider>,
    )
    fireEvent.change(screen.getByLabelText('Filter components'), { target: { value: 'swarm' } })
    const nav = screen.getByRole('navigation', { name: 'Component sections' })
    expect(nav).toHaveTextContent('Swarm Map')
    expect(nav).not.toHaveTextContent('SOAR Builder')
  })

  it('opens the composed FindingDrawerV2', () => {
    render(
      <ThemeProvider>
        <AdvancedShowcase />
      </ThemeProvider>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Open finding drawer/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})
