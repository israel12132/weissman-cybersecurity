import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, within, cleanup } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key, opts) => {
      if (key === 'playbooks.canvas.label') return 'Playbook canvas'
      if (key === 'playbooks.palette.group') return 'Playbook node palette'
      if (key === 'playbooks.palette.add') return `Add ${opts?.type} node`
      if (key === 'playbooks.inspector.title') return 'Inspector'
      if (key === 'playbooks.inspector.no_selection') return 'Select a node'
      if (key === 'playbooks.nodes.trigger') return 'Trigger'
      if (key === 'playbooks.action.set_status') return 'Set Status'
      if (key === 'playbooks.action.isolate_host') return 'Isolate Host'
      if (key === 'playbooks.canvas.issue_no_trigger') return 'Add a Trigger node'
      if (opts?.count != null) return `${key}:${opts.count}`
      return key
    },
    i18n: { language: 'en', dir: () => 'ltr' },
  }),
}))

// ReactFlow needs a real layout/WebGL environment, so we stub @xyflow with a
// lightweight mock that still holds node state — enough to verify the canvas
// wiring (palette add → node appears on the canvas).
vi.mock('@xyflow/react', async () => {
  const React = await import('react')
  return {
    ReactFlow: ({ nodes, edges, onConnect, onSelectionChange }) => (
      <div data-testid="reactflow">
        {(nodes || []).map((n) => (
          <button
            key={n.id}
            type="button"
            data-node-id={n.id}
            onClick={() => onSelectionChange?.({ nodes: [n], edges: [] })}
          >
            {n.data?.label}
          </button>
        ))}
        {(edges || []).map((e) => (
          <span key={e.id || `${e.source}-${e.target}`} data-edge={`${e.source}->${e.target}`} />
        ))}
        {(nodes || []).length >= 2 && (
          <button
            type="button"
            data-testid="mock-connect"
            onClick={() => onConnect?.({ source: nodes[0].id, target: nodes[1].id })}
          >
            connect
          </button>
        )}
      </div>
    ),
    ReactFlowProvider: ({ children }) => <>{children}</>,
    Background: () => null,
    Controls: () => null,
    MiniMap: () => null,
    Handle: () => null,
    Position: { Top: 'top', Bottom: 'bottom' },
    MarkerType: { ArrowClosed: 'arrowclosed' },
    addEdge: (edge, eds) => [...eds, { ...edge, id: edge.id || `e-${edge.source}-${edge.target}` }],
    useReactFlow: () => ({
      screenToFlowPosition: ({ x, y }) => ({ x, y }),
      fitView: () => {},
    }),
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

  it('adds a node on drop with the text/plain drag fallback', () => {
    render(<PlaybookCanvas />)
    const canvas = screen.getByLabelText('Playbook canvas')
    fireEvent.drop(canvas, {
      dataTransfer: {
        getData: (mime) => (mime === 'text/plain' ? 'weissman-node:delay' : ''),
      },
      clientX: 80,
      clientY: 80,
    })
    expect(within(screen.getByTestId('reactflow')).getByText('Delay')).toBeInTheDocument()
  })

  it('hydrates from playbook DSL and compiles added actions', () => {
    const onDslChange = vi.fn()
    render(
      <PlaybookCanvas
        trigger={{ severity: ['critical'] }}
        actions={[{ kind: 'set_status', params: { status: 'IN_PROGRESS' } }]}
        onDslChange={onDslChange}
      />,
    )
    expect(within(screen.getByTestId('reactflow')).getByText('Trigger')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Add Isolate Host node' }))
    const last = onDslChange.mock.calls.at(-1)[0]
    expect(last.actions.some((a) => a.kind === 'isolate_host')).toBe(true)
    expect(last.trigger.severity).toEqual(['critical'])
    expect(last.trigger._canvas.nodes.length).toBeGreaterThan(1)
  })

  it('wires two nodes through onConnect', () => {
    const onChange = vi.fn()
    render(<PlaybookCanvas onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add Trigger node' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add Action node' }))
    fireEvent.click(screen.getByTestId('mock-connect'))
    const last = onChange.mock.calls.at(-1)[0]
    expect(last.edges.length).toBeGreaterThan(0)
  })
})
