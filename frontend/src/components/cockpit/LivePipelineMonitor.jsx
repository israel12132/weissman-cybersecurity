/**
 * Live Pipeline Monitor — Stages 0–4 and true DAG tree in real time. Pause, resume, skip per client.
 * Data from GET /api/pipeline/state, GET /api/dag, and SSE pipeline_stage events.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { Layers, Pause, Play, Radio, GitBranch } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const STAGE_LABELS = [
  'Global Intel (Zero-Day Radar)',
  'Deep Discovery (OSINT, ASM)',
  'Vulnerability Scanning',
  'Kill Shot (PoE, Deception)',
  'Compliance (Audit, PDF)',
]

function nodeStatusForStage(stageToNodes, currentStage, nodeId) {
  if (!stageToNodes || currentStage == null) return 'pending'
  for (let s = 0; s <= 4; s++) {
    const nodes = stageToNodes[String(s)] || []
    if (nodes.includes(nodeId)) {
      if (s < currentStage) return 'done'
      if (s === currentStage) return 'current'
      return 'pending'
    }
  }
  return 'pending'
}

function buildDagLayout(dag, stageToNodes, currentStage) {
  if (!dag?.nodes?.length) return { nodes: [], edges: [] }
  const edges = (dag.edges || []).map(e => ({
    id: `e-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    type: 'smoothstep',
  }))
  const inDegree = {}
  dag.nodes.forEach(n => { inDegree[n.id] = 0 })
  ;(dag.edges || []).forEach(e => { inDegree[e.target] = (inDegree[e.target] || 0) + 1 })
  const layers = []
  const assigned = new Set()
  let remaining = dag.nodes.map(n => n.id)
  while (remaining.length) {
    const layer = remaining.filter(id => inDegree[id] === 0)
    if (!layer.length) break
    layer.forEach(id => { assigned.add(id) })
    layers.push(layer)
    ;(dag.edges || []).forEach(e => {
      if (layer.includes(e.source)) inDegree[e.target] = Math.max(0, (inDegree[e.target] || 0) - 1)
    })
    remaining = remaining.filter(id => !assigned.has(id))
  }
  const nodeMap = Object.fromEntries(dag.nodes.map(n => [n.id, n]))
  const flowNodes = []
  const gapX = 168
  const gapY = 64
  layers.forEach((layer, li) => {
    layer.forEach((id, i) => {
      const status = nodeStatusForStage(stageToNodes, currentStage, id)
      const n = nodeMap[id] || { id, label: id }
      flowNodes.push({
        id: String(n.id),
        type: 'default',
        position: { x: i * gapX, y: li * gapY },
        data: { label: n.label || n.id },
        className: `dag-node dag-node-${status}`,
      })
    })
  })
  return { nodes: flowNodes, edges }
}

export default function LivePipelineMonitor() {
  const { selectedClientId } = useClient()
  const { lastTelemetry } = useWarRoom?.() || {}
  const [viewMode, setViewMode] = useState('stages') // 'stages' | 'dag'
  const [dag, setDag] = useState(null)
  const [runId, setRunId] = useState(null)
  const [states, setStates] = useState([])
  const [stageLabels, setStageLabels] = useState(STAGE_LABELS)
  const [loading, setLoading] = useState(false)
  const [patching, setPatching] = useState(false)
  const [dagNodes, setDagNodes, onDagNodesChange] = useNodesState([])
  const [dagEdges, setDagEdges, onDagEdgesChange] = useEdgesState([])

  const fetchState = useCallback(async () => {
    setLoading(true)
    try {
      const url = selectedClientId
        ? `/api/pipeline/state?client_id=${encodeURIComponent(selectedClientId)}`
        : '/api/pipeline/state'
      const r = await apiFetch(url)
      if (r.ok) {
        const d = await r.json()
        setRunId(d.run_id ?? null)
        setStates(d.states ?? [])
        if (Array.isArray(d.stage_labels) && d.stage_labels.length) {
          setStageLabels(d.stage_labels.map((s) => s.label || s))
        }
      }
    } catch (_) {
      setStates([])
      setRunId(null)
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  const fetchDag = useCallback(async () => {
    try {
      const r = await apiFetch('/api/dag')
      if (r.ok) setDag(await r.json())
    } catch (_) {
      setDag(null)
    }
  }, [])

  useEffect(() => {
    fetchState()
  }, [fetchState])

  useEffect(() => {
    fetchDag()
  }, [fetchDag])

  useEffect(() => {
    if (lastTelemetry?.event === 'pipeline_stage') {
      fetchState()
    }
  }, [lastTelemetry?.event, lastTelemetry?.run_id, lastTelemetry?.client_id, fetchState])

  const patchState = async (payload) => {
    if (!selectedClientId && !payload.client_id) return
    setPatching(true)
    try {
      await apiFetch('/api/pipeline/state', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: runId,
          client_id: payload.client_id || selectedClientId,
          ...payload,
        }),
      })
      await fetchState()
    } catch (_) {}
    setPatching(false)
  }

  const displayStates = selectedClientId
    ? states.filter((s) => s.client_id === selectedClientId)
    : states

  const currentStage = useMemo(() => {
    const s = displayStates[0]
    return s?.current_stage != null ? Number(s.current_stage) : null
  }, [displayStates])

  useEffect(() => {
    if (viewMode !== 'dag' || !dag?.nodes?.length) return
    const { nodes, edges } = buildDagLayout(dag, dag.stage_to_nodes || {}, currentStage)
    setDagNodes(nodes)
    setDagEdges(edges)
  }, [viewMode, dag, currentStage])

  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-[#22d3ee]" />
          <span className="font-semibold text-white">Live Pipeline Monitor</span>
          {runId != null && (
            <span className="text-xs text-white/50 font-mono">Run #{runId}</span>
          )}
          <div className="flex rounded-lg border border-white/10 overflow-hidden">
            <button
              type="button"
              onClick={() => setViewMode('stages')}
              className={`px-2 py-1 text-xs ${viewMode === 'stages' ? 'bg-[#22d3ee]/20 text-[#22d3ee]' : 'text-white/60 hover:text-white'}`}
            >
              Stages
            </button>
            <button
              type="button"
              onClick={() => setViewMode('dag')}
              className={`px-2 py-1 text-xs flex items-center gap-1 ${viewMode === 'dag' ? 'bg-[#22d3ee]/20 text-[#22d3ee]' : 'text-white/60 hover:text-white'}`}
            >
              <GitBranch className="w-3 h-3" /> DAG tree
            </button>
          </div>
        </div>
        <button
          type="button"
          onClick={fetchState}
          disabled={loading}
          className="text-xs text-[#22d3ee] hover:underline disabled:opacity-50"
        >
          Refresh
        </button>
      </div>
      <div className="p-4 space-y-4">
        {viewMode === 'dag' && (
          <div className="rounded-xl border border-white/10 bg-black/30 overflow-hidden" style={{ height: 340 }}>
            <ReactFlow
              nodes={dagNodes}
              edges={dagEdges}
              onNodesChange={onDagNodesChange}
              onEdgesChange={onDagEdgesChange}
              fitView
              className="bg-transparent"
              nodeClassName="dag-node"
            >
              <Background color="#22d3ee" gap={12} size={0.5} />
              <Controls className="bg-black/60 border-white/10" />
              <MiniMap className="bg-black/60" />
            </ReactFlow>
            <style>{`
              .dag-node-done .react-flow__node { border-color: #10b981; background: rgba(16,185,129,0.15); }
              .dag-node-current .react-flow__node { border-color: #22d3ee; background: rgba(34,211,238,0.15); animation: pulse 1.5s ease-in-out infinite; }
              .dag-node-pending .react-flow__node { border-color: rgba(255,255,255,0.15); background: rgba(255,255,255,0.05); }
            `}</style>
          </div>
        )}
        {loading && !states.length ? (
          <p className="text-sm text-white/50">Loading pipeline state…</p>
        ) : !runId ? (
          <p className="text-sm text-white/50">No active run. Start a scan to see stages 0→4.</p>
        ) : viewMode === 'stages' ? (
          <>
            <div className="grid grid-cols-1 gap-4">
              {displayStates.map((s) => (
                <div
                  key={s.client_id}
                  className="rounded-xl border border-white/10 bg-black/30 p-3"
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-white/80">
                      {s.client_id === '__global__' ? 'Global' : s.client_id}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => patchState({ client_id: s.client_id, paused: !s.paused })}
                        disabled={patching}
                        className="flex items-center gap-1 px-2 py-1 rounded-lg border border-white/20 text-xs text-white/80 hover:bg-white/10 disabled:opacity-50"
                      >
                        {s.paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
                        {s.paused ? 'Resume' : 'Pause'}
                      </button>
                      <select
                        className="bg-black/60 border border-white/10 rounded-lg text-xs text-white px-2 py-1"
                        value=""
                        onChange={(e) => {
                          const v = e.target.value
                          if (v === '') return
                          const stage = parseInt(v, 10)
                          if (!Number.isNaN(stage)) patchState({ client_id: s.client_id, skip_to_stage: stage })
                          e.target.value = ''
                        }}
                      >
                        <option value="">Skip to…</option>
                        {stageLabels.map((label, i) => (
                          <option key={i} value={i}>
                            Stage {i}: {label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {stageLabels.map((label, i) => {
                      const current = Number(s.current_stage)
                      const status = i < current ? 'done' : i === current ? 'current' : 'pending'
                      return (
                        <div
                          key={i}
                          className={`flex items-center gap-1.5 px-2 py-1.5 rounded-lg border text-[10px] ${
                            status === 'done'
                              ? 'border-[#10b981]/50 bg-[#10b981]/10 text-[#10b981]'
                              : status === 'current'
                                ? 'border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee]'
                                : 'border-white/10 bg-white/5 text-white/50'
                          }`}
                        >
                          {status === 'current' && <Radio className="w-3 h-3 animate-pulse" />}
                          <span className="truncate max-w-[140px]">S{i}: {label.split('(')[0].trim()}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
            {displayStates.length === 0 && runId && (
              <p className="text-sm text-white/50">No pipeline state for this client yet.</p>
            )}
          </>
        ) : null}
      </div>
    </div>
  )
}
