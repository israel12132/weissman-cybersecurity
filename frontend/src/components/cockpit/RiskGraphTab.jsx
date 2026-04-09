/**
 * CNAPP Layer 1: Contextual Risk Graph — zoomable graph of assets, identities, findings, network.
 * All data from live API; no hardcoded nodes.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useClient } from '../../context/ClientContext'
import { Network, RefreshCw, AlertCircle } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const NODE_WIDTH = 160
const NODE_HEIGHT = 48
const LAYOUT_GAP = 120

function layoutFromApi(nodes, edges) {
  if (!nodes?.length) return { nodes: [], edges: [] }
  const byType = {}
  nodes.forEach(n => {
    const t = n.node_type || 'asset'
    if (!byType[t]) byType[t] = []
    byType[t].push(n)
  })
  let y = 80
  const flowNodes = []
  const typeOrder = ['asset', 'physical_asset', 'identity', 'network', 'finding', 'package', 'repo']
  typeOrder.forEach((t) => {
    const list = byType[t] || []
    list.forEach((n, i) => {
      const nt = n.node_type || 'asset'
      const border =
        nt === 'physical_asset'
          ? '1px solid rgba(245, 158, 11, 0.65)'
          : nt === 'finding'
            ? '1px solid rgba(248, 113, 113, 0.5)'
            : '1px solid rgba(34, 211, 238, 0.35)'
      const bg =
        nt === 'physical_asset' ? 'rgba(120, 53, 15, 0.35)' : nt === 'finding' ? 'rgba(127, 29, 29, 0.35)' : 'rgba(0,0,0,0.55)'
      flowNodes.push({
        id: String(n.id),
        type: 'default',
        position: { x: 80 + (i % 4) * (NODE_WIDTH + LAYOUT_GAP), y: y + Math.floor(i / 4) * (NODE_HEIGHT + 40) },
        data: {
          label: n.label || n.node_type || String(n.id),
          nodeType: n.node_type,
          externalId: n.external_id,
        },
        className: `risk-node risk-node-${nt.replace(/_/g, '-')}`,
        style: { border, background: bg },
      })
    })
    if (list.length) y += Math.ceil(list.length / 4) * (NODE_HEIGHT + 40) + 60
  })
  const flowEdges = (edges || []).map(e => ({
    id: `e-${e.source}-${e.target}`,
    source: String(e.source),
    target: String(e.target),
    type: 'smoothstep',
    label: e.edge_type,
    labelBgStyle: { fill: 'rgba(10,10,10,0.95)' },
    labelStyle: { fill: '#22d3ee', fontSize: 10 },
  }))
  return { nodes: flowNodes, edges: flowEdges }
}

export default function RiskGraphTab() {
  const { selectedClientId } = useClient()
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [loading, setLoading] = useState(false)
  const [building, setBuilding] = useState(false)
  const [error, setError] = useState(null)

  const fetchGraph = useCallback(async () => {
    if (!selectedClientId) {
      setNodes([])
      setEdges([])
      return
    }
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/risk-graph`)
      if (!r.ok) {
        setError('Failed to load risk graph')
        return
      }
      const d = await r.json()
      const { nodes: n, edges: e } = layoutFromApi(d.nodes || [], d.edges || [])
      setNodes(n)
      setEdges(e)
    } catch (_) {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, setNodes, setEdges])

  useEffect(() => {
    fetchGraph()
  }, [fetchGraph])

  const buildGraph = async () => {
    if (!selectedClientId) return
    setBuilding(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/risk-graph`, {
        method: 'POST',
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setError(d.error || 'Build failed')
        return
      }
      await fetchGraph()
    } catch (_) {
      setError('Build request failed')
    } finally {
      setBuilding(false)
    }
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        Select a client to view the Contextual Risk Graph.
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full min-h-[500px]">
      <div className="flex items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-[#22d3ee]" />
          <h2 className="text-lg font-semibold text-white tracking-wide">Contextual Risk Graph</h2>
        </div>
        <button
          type="button"
          onClick={buildGraph}
          disabled={building}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 disabled:opacity-50 transition-all"
        >
          <RefreshCw className={`w-4 h-4 ${building ? 'animate-spin' : ''}`} />
          {building ? 'Building…' : 'Build / Refresh Graph'}
        </button>
      </div>
      {error && (
        <div className="flex items-center gap-2 mb-4 px-4 py-2 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}
      <div className="flex-1 rounded-2xl bg-black/60 backdrop-blur-md border border-white/10 overflow-hidden min-h-[400px]">
        {loading ? (
          <div className="flex items-center justify-center h-full text-white/50">Loading graph…</div>
        ) : nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-white/50 gap-2">
            <p>No graph data. Run scans (ASM, findings, identity contexts) then click Build.</p>
            <button
              type="button"
              onClick={buildGraph}
              disabled={building}
              className="px-4 py-2 rounded-lg border border-white/20 text-white/80 hover:bg-white/5"
            >
              Build graph
            </button>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            className="bg-[#0a0a0a]"
            nodeClassName="rounded-lg border border-white/10 bg-black/60 text-white"
          >
            <Background color="#333" gap={16} />
            <Controls className="!bg-black/80 !border-white/10" />
            <MiniMap
              className="!bg-black/80 !border-white/10"
              nodeColor={(n) =>
                n.data?.nodeType === 'finding' ? '#f87171' : n.data?.nodeType === 'physical_asset' ? '#f59e0b' : '#22d3ee'
              }
            />
          </ReactFlow>
        )}
      </div>
    </div>
  )
}
