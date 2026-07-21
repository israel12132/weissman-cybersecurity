/**
 * Module 4: Semantic Logic Engine — State Machine visualizer + LLM Reasoning terminal.
 * Fetches state machine from OpenAPI and last reasoning log from backend.
 */
import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { apiFetch } from '../utils/apiFetch'
import StandaloneLabShell from './ui/StandaloneLabShell'
import Button from './ui/Button'

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

const NS = 'components.tools.semanticLogicEngine'

export default function SemanticLogicEngine() {
  const { t } = useTranslation()
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
      apiFetch(`/api/clients/${clientId}/semantic-state-machine`),
      apiFetch(`/api/clients/${clientId}/semantic-logic/reasoning`),
    ])
      .then(([sm, log]) => {
        setStateMachine(sm)
        setReasoning(log?.log ?? '')
        const { nodes: n, edges: e } = layoutStateMachine(sm.nodes || [], sm.edges || [])
        setNodes(n)
        setEdges(e)
      })
      .catch(e => setError(e?.message || t(`${NS}.load_failed`)))
      .finally(() => setLoading(false))
  }, [clientId, setNodes, setEdges, t])

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [load])

  if (loading && !stateMachine.nodes?.length) {
    return (
      <div className="min-h-screen bg-[var(--bg-0)] text-[var(--text-secondary)] flex items-center justify-center">
        <p className="text-cyan-400">{t(`${NS}.loading`)}</p>
      </div>
    )
  }

  return (
    <StandaloneLabShell
      title={t(`${NS}.title`)}
      subtitle={stateMachine.target ? t(`${NS}.target_label`, { target: stateMachine.target }) : undefined}
      actions={(
        <Button variant="unstyled" type="button" onClick={load} className="text-sm text-[var(--text-tertiary)] hover:text-cyan-400">
          {t(`${NS}.refresh`)}
        </Button>
      )}
      contentClassName="p-0"
    >
      {error && (
        <div className="mx-6 mt-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}
      <div className="flex-1 flex gap-4 p-4" style={{ minHeight: 'calc(100vh - 120px)' }}>
        <div className="flex-1 rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/40 overflow-hidden">
          <div className="px-4 py-2 border-b border-[var(--border-strong)] text-sm font-medium text-[var(--text-secondary)]">{t(`${NS}.state_machine_title`)}</div>
          <div className="h-full min-h-[400px]">
            {nodes.length > 0 ? (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                fitView
                className="bg-[var(--bg-0)]"
                style={{ background: '#0f172a' }}
              >
                <Background color="#334155" gap={16} />
                <Controls className="bg-[var(--bg-3)]/90 border-[var(--border-strong)]" />
                <MiniMap nodeColor="#0d9488" className="bg-[var(--bg-3)]/90" />
              </ReactFlow>
            ) : (
              <div className="flex items-center justify-center h-full text-[var(--text-muted)] text-sm">
                {stateMachine.message || t(`${NS}.no_openapi`)}
              </div>
            )}
          </div>
        </div>
        <div className="w-[420px] flex flex-col rounded-xl border border-[var(--border-strong)]/80 bg-[var(--bg-1)]/40 overflow-hidden">
          <div className="px-4 py-2 border-b border-[var(--border-strong)] text-sm font-medium text-[var(--text-secondary)]">{t(`${NS}.reasoning_title`)}</div>
          <pre className="flex-1 p-4 overflow-auto text-xs text-[var(--text-tertiary)] font-mono whitespace-pre-wrap bg-[var(--bg-0)]/80 min-h-[200px]">
            {reasoning || t(`${NS}.no_reasoning`)}
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
    </StandaloneLabShell>
  )
}
