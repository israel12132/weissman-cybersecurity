import { useCallback, useEffect, useRef } from 'react'
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  addEdge,
  useNodesState,
  useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { cn } from '../../lib/cn'
import NodePalette from './NodePalette.jsx'
import { makeNode, serializeGraph } from '../../lib/playbookFlow.js'

const NODE_ACCENT = {
  trigger: 'border-accent-cyan/50',
  action: 'border-accent-violet/50',
  condition: 'border-severity-medium/50',
  delay: 'border-border-strong',
  notify: 'border-severity-info/50',
}

/** Custom @xyflow node rendered with design-system tokens + connect handles. */
function FlowPlaybookNode({ data }) {
  return (
    <div
      className={cn(
        'rounded-lg border bg-bg-2 px-3 py-2 text-xs font-medium text-text-primary shadow-sm',
        NODE_ACCENT[data?.nodeType] ?? 'border-border-default',
      )}
    >
      <Handle type="target" position={Position.Top} className="!bg-border-strong" />
      {data?.label}
      <Handle type="source" position={Position.Bottom} className="!bg-border-strong" />
    </div>
  )
}

const nodeTypes = { playbook: FlowPlaybookNode }

function CanvasInner({ initialNodes = [], initialEdges = [], onChange, height = 360, className }) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const idRef = useRef(initialNodes.length)
  const wrapperRef = useRef(null)

  useEffect(() => {
    onChange?.(serializeGraph(nodes, edges))
  }, [nodes, edges, onChange])

  const onConnect = useCallback(
    (params) => setEdges((eds) => addEdge({ ...params, markerEnd: { type: MarkerType.ArrowClosed } }, eds)),
    [setEdges],
  )

  const addNodeOfType = useCallback(
    (type, position) => {
      idRef.current += 1
      setNodes((nds) => [...nds, makeNode(type, idRef.current, position)])
    },
    [setNodes],
  )

  const onDrop = useCallback(
    (e) => {
      e.preventDefault()
      const type = e.dataTransfer?.getData('application/weissman-node')
      if (!type) return
      const bounds = wrapperRef.current?.getBoundingClientRect?.() || { left: 0, top: 0 }
      addNodeOfType(type, { x: e.clientX - bounds.left, y: e.clientY - bounds.top })
    },
    [addNodeOfType],
  )

  return (
    <div className={cn('grid gap-3 sm:grid-cols-[10rem_1fr]', className)}>
      <NodePalette onAdd={(t) => addNodeOfType(t, { x: 60, y: 40 + nodes.length * 20 })} />
      <div
        ref={wrapperRef}
        onDrop={onDrop}
        onDragOver={(e) => {
          e.preventDefault()
          if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'
        }}
        aria-label="Playbook canvas"
        className="overflow-hidden rounded-xl border border-border-default bg-bg-1"
        style={{ height }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1e293b" gap={18} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  )
}

/**
 * PlaybookCanvas — an editable SOAR playbook flow editor on @xyflow. Drag node
 * types from the palette onto the canvas (or click to add), wire them by
 * dragging between handles, and reposition freely. Emits the serialized graph
 * via `onChange`.
 *
 * @param {Array} [initialNodes] @param {Array} [initialEdges]
 * @param {(graph:{nodes,edges})=>void} [onChange] @param {number} [height=360]
 */
export default function PlaybookCanvas(props) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  )
}

export { PlaybookCanvas }
