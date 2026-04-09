/**
 * Module 4: Semantic Logic Engine — State Machine visualizer + LLM Reasoning terminal.
 * Fetches state machine from OpenAPI and last reasoning log from backend.
 */
import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { apiFetch } from '../lib/apiBase'

const CENTER_X = 400
const CENTER_Y = 280
const RADIUS = 180

function layoutStateMachine(apiNodes, apiEdges) {
  if (!apiNodes?.length) return { nodes: [], edges: [] }
  const nodes = []
  const edges = []
  apiNodes.forEach((n, i) => {
    const angle = (i / Math.max(apiNodes.length, 1)) * 2 * Math.PI - Math.PI / 2
    nodes.push({
      id: n.id,
      type: 'stateNode',
      position: {
        x: CENTER_X + RADIUS * Math.cos(angle) - 60,
        y: CENTER_Y + RADIUS * Math.sin(angle) - 20,
      },
      data: { label: `${n.method} ${n.path}`, ...n },
    })
  })
  ;(apiEdges || []).forEach(e => {
    edges.push({
      id: e.id || `e-${e.from_id}-${e.to_id}`,
      source: e.from_id,
      target: e.to_id,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed },
      label: e.edge_type || 'sequence',
      labelStyle: { fill: '#94a3b8', fontSize: 10 },
    })
  })
  return { nodes, edges }
}

function StateNode({ data }) {
  return (
    <div className="semantic-node-inner">
      <div className="semantic-node-method">{data.method}</div>
      <div className="semantic-node-path">{data.path}</div>
    </div>
  )
}

const nodeTypes = { stateNode: StateNode }

export default function SemanticLogicEngine() {
  const { clientId } = useParams()
  const [stateMachine, setStateMachine] = useState({ nodes: [], edges: [], target: '', message: '' })
  const [reasoning, setReasoning] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  const load = useCallback(() => {
    if (!clientId) return
    setLoading(true)
    Promise.all([
      apiFetch(`/api/clients/${clientId}/semantic-state-machine`).then((r) => r.json()),
      apiFetch(`/api/clients/${clientId}/semantic-logic/reasoning`).then((r) => r.json()),
    ])
      .then(([sm, log]) => {
        setStateMachine(sm)
        setReasoning(log?.log ?? '')
        const { nodes: n, edges: e } = layoutStateMachine(sm.nodes || [], sm.edges || [])
        setNodes(n)
        setEdges(e)
      })
      .catch(e => setError(e?.message || 'Load failed'))
      .finally(() => setLoading(false))
  }, [clientId, setNodes, setEdges])

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [load])

  if (loading && !stateMachine.nodes?.length) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <p className="text-cyan-400">Loading Semantic Logic Engine…</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col">
      <header className="flex items-center justify-between border-b border-slate-700 px-6 py-3">
        <h1 className="text-lg font-bold text-cyan-400">Semantic Logic Engine</h1>
        <div className="flex items-center gap-4">
          {stateMachine.target && <span className="text-xs text-slate-500">Target: {stateMachine.target}</span>}
          <button type="button" onClick={load} className="text-sm text-slate-400 hover:text-cyan-400">Refresh</button>
          <Link to="/" className="text-sm text-slate-400 hover:text-cyan-400">← War Room</Link>
        </div>
      </header>
      {error && (
        <div className="mx-6 mt-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}
      <div className="flex-1 flex gap-4 p-4" style={{ minHeight: 'calc(100vh - 120px)' }}>
        <div className="flex-1 rounded-xl border border-slate-600/80 bg-slate-900/40 overflow-hidden">
          <div className="px-4 py-2 border-b border-slate-600 text-sm font-medium text-slate-300">State Machine (API flow)</div>
          <div className="h-full min-h-[400px]">
            {nodes.length > 0 ? (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                fitView
                className="bg-slate-950"
                style={{ background: '#0f172a' }}
              >
                <Background color="#334155" gap={16} />
                <Controls className="bg-slate-800/90 border-slate-600" />
                <MiniMap nodeColor="#0d9488" className="bg-slate-800/90" />
              </ReactFlow>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-sm">
                {stateMachine.message || 'No OpenAPI/Swagger at target. Add a client and run a scan.'}
              </div>
            )}
          </div>
        </div>
        <div className="w-[420px] flex flex-col rounded-xl border border-slate-600/80 bg-slate-900/40 overflow-hidden">
          <div className="px-4 py-2 border-b border-slate-600 text-sm font-medium text-slate-300">LLM Reasoning</div>
          <pre className="flex-1 p-4 overflow-auto text-xs text-slate-400 font-mono whitespace-pre-wrap bg-slate-950/80 min-h-[200px]">
            {reasoning || 'No reasoning log yet. Run a scan with Semantic Logic Engine enabled.'}
          </pre>
        </div>
      </div>
      <style>{`
        .semantic-node-inner {
          padding: 10px 14px;
          border-radius: 8px;
          border: 1px solid #0d9488;
          background: rgba(13,148,136,0.12);
          min-width: 100px;
          text-align: center;
        }
        .semantic-node-method { font-size: 11px; color: #5eead4; font-weight: 600; }
        .semantic-node-path { font-size: 10px; color: #94a3b8; margin-top: 4px; word-break: break-all; }
      `}</style>
    </div>
  )
}
