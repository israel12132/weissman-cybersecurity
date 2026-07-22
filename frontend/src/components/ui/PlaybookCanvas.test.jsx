import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, within, cleanup } from '@testing-library/react'

// ReactFlow needs a real layout/WebGL environment, so we stub @xyflow with a
// lightweight mock that still holds node state — enough to verify the canvas
// wiring (palette add → node appears on the canvas).
vi.mock('@xyflow/react', async () => {
  const React = await import('react')
  return {
    ReactFlow: ({ nodes }) => (
      <div data-testid="reactflow">
        {(nodes || []).map((n) => (
          <span key={n.id} data-node-id={n.id}>
            {n.data?.label}
          </span>
        ))}
      </div>
    ),
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

import PlaybookCanvas from './PlaybookCanvas.jsx'

afterEach(cleanup)

describe('PlaybookCanvas', () => {
  it('renders the palette and an empty canvas', () => {
    render(<PlaybookCanvas />)
    expect(screen.getByRole('button', { name: 'Add Trigger node' })).toBeInTheDocument()
    expect(screen.getByLabelText('Playbook canvas')).toBeInTheDocument()
    expect(within(screen.getByTestId('reactflow')).queryByText('Action')).not.toBeInTheDocument()
  })

  it('adds a node to the canvas when a palette item is activated', () => {
    render(<PlaybookCanvas />)
    fireEvent.click(screen.getByRole('button', { name: 'Add Action node' }))
    // The new node label shows up inside the canvas (not just the palette).
    expect(within(screen.getByTestId('reactflow')).getByText('Action')).toBeInTheDocument()
  })

  it('emits the serialized graph via onChange', () => {
    const onChange = vi.fn()
    render(<PlaybookCanvas onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add Notify node' }))
    const last = onChange.mock.calls.at(-1)[0]
    expect(last.nodes.some((n) => n.type === 'notify')).toBe(true)
  })

  it('adds a node on drop with the drag payload', () => {
    render(<PlaybookCanvas />)
    const canvas = screen.getByLabelText('Playbook canvas')
    fireEvent.drop(canvas, {
      dataTransfer: { getData: () => 'condition' },
      clientX: 100,
      clientY: 100,
    })
    expect(within(screen.getByTestId('reactflow')).getByText('Condition')).toBeInTheDocument()
  })
})
