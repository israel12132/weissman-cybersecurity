import { useMemo } from 'react'
import { ReactFlow, Background, Controls, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'

const ACTION_COLORS = {
  set_status: '#22d3ee',
  slack_notify: '#a78bfa',
  webhook: '#34d399',
  http_post: '#34d399',
  open_pr: '#f59e0b',
  isolate_host: '#ef4444',
  page_oncall: '#fb7185',
}

const nodeBase = {
  background: '#0b1220',
  color: '#e2e8f0',
  borderRadius: 8,
  padding: 8,
  width: 220,
  fontSize: 12,
}

/**
 * Read-only DAG visualization of a SOAR playbook: the trigger flows into its ordered actions.
 * Reuses the existing linear schema (`trigger` + `actions[]`) — it does NOT change the saved
 * shape, so it complements the linear editor without risk. Clicking an action node calls
 * `onSelectAction(index)`. (Conditional branches would require a backend schema change.)
 */
export default function PlaybookGraph({ trigger, actions = [], onSelectAction, onDryRun }) {
  const { nodes, edges } = useMemo(() => {
    const sev = Array.isArray(trigger?.severity) && trigger.severity.length
      ? trigger.severity.join(', ')
      : 'any'
    const triggerLabel = `WHEN severity: ${sev}${trigger?.kev ? ' · KEV' : ''}`

    const nodeList = [
      {
        id: 'trigger',
        position: { x: 0, y: 0 },
        data: { label: triggerLabel },
        style: { ...nodeBase, border: '1px solid #334155' },
      },
      ...actions.map((a, i) => ({
        id: `a${i}`,
        position: { x: 0, y: (i + 1) * 92 },
        data: { label: `${i + 1}. ${a.kind || 'action'}` },
        style: { ...nodeBase, border: `1px solid ${ACTION_COLORS[a.kind] || '#475569'}`, cursor: 'pointer' },
      })),
    ]

    const edgeList = []
    let prev = 'trigger'
    actions.forEach((_, i) => {
      edgeList.push({
        id: `e-${prev}-a${i}`,
        source: prev,
        target: `a${i}`,
        markerEnd: { type: MarkerType.ArrowClosed },
        style: { stroke: '#475569' },
      })
      prev = `a${i}`
    })
    return { nodes: nodeList, edges: edgeList }
  }, [trigger, actions])

  return (
    <div className="rounded-lg border border-white/10 bg-[#060a12]">
      <div style={{ height: 340 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          onNodeClick={(_e, node) => {
            const m = /^a(\d+)$/.exec(node.id)
            if (m && onSelectAction) onSelectAction(Number(m[1]))
          }}
        >
          <Background color="#1e293b" gap={18} />
          <Controls className="bg-slate-800/90 border-slate-600" showInteractive={false} />
        </ReactFlow>
      </div>
      {onDryRun && (
        <div className="p-2 border-t border-white/10 flex justify-end">
          <button
            type="button"
            onClick={onDryRun}
            className="text-[11px] font-mono px-2 py-1 rounded border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10"
          >
            Dry-run playbook
          </button>
        </div>
      )}
    </div>
  )
}
