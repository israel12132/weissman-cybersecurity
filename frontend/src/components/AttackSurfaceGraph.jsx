/**
 * Module 3: Attack Surface Graph — live nodes/edges from Rust backend.
 * Central root domain, subdomains radiating out, cloud targets; secure = green/slate, exposed/takeover = crimson + pulse.
 */
import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { apiFetch } from '../lib/apiBase'
import StandaloneLabShell from './ui/StandaloneLabShell'

const CENTER_X = 500
const CENTER_Y = 350
const RADIUS_SUBDOMAIN = 220
const RADIUS_CLOUD = 380
const RADIUS_EXPLOIT = 320

function layoutNodes(apiNodes, apiEdges) {
  if (!apiNodes?.length) return { nodes: [], edges: [] }
  const root = apiNodes.find(n => n.node_type === 'root')
  const subdomains = apiNodes.filter(n => n.node_type === 'subdomain')
  const clouds = apiNodes.filter(n => n.node_type === 'cloud_target')
  const exploits = apiNodes.filter(n => n.node_type === 'exploit')
  const nodes = []
  const edges = []

  if (root) {
    nodes.push({
      id: root.id,
      type: 'asmNode',
      position: { x: CENTER_X - 40, y: CENTER_Y - 20 },
      data: { label: root.label, ...root },
      className: 'asm-root',
    })
  }
  subdomains.forEach((n, i) => {
    const angle = (i / Math.max(subdomains.length, 1)) * 2 * Math.PI - Math.PI / 2
    nodes.push({
      id: n.id,
      type: 'asmNode',
      position: {
        x: CENTER_X + RADIUS_SUBDOMAIN * Math.cos(angle) - 50,
        y: CENTER_Y + RADIUS_SUBDOMAIN * Math.sin(angle) - 18,
      },
      data: { label: n.label, ...n },
      className: n.status === 'takeover' ? 'asm-takeover' : n.status === 'exposed' ? 'asm-exposed' : 'asm-secure',
    })
  })
  clouds.forEach((n, i) => {
    const angle = (i / Math.max(clouds.length, 1)) * 2 * Math.PI
    nodes.push({
      id: n.id,
      type: 'asmNode',
      position: {
        x: CENTER_X + RADIUS_CLOUD * Math.cos(angle) - 60,
        y: CENTER_Y + RADIUS_CLOUD * Math.sin(angle) - 12,
      },
      data: { label: n.label, ...n },
      className: 'asm-cloud',
    })
  })
  exploits.forEach((n, i) => {
    const angle = (i / Math.max(exploits.length, 1)) * 2 * Math.PI + Math.PI / 4
    nodes.push({
      id: n.id,
      type: 'asmNode',
      position: {
        x: CENTER_X + RADIUS_EXPLOIT * Math.cos(angle) - 55,
        y: CENTER_Y + RADIUS_EXPLOIT * Math.sin(angle) - 14,
      },
      data: { label: n.label, ...n },
      className: 'asm-exploit',
    })
  })

  ;(apiEdges || []).forEach(e => {
    edges.push({
      id: e.id || `e-${e.from_id}-${e.to_id}`,
      source: e.from_id,
      target: e.to_id,
      type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed },
      label: e.edge_type || 'CNAME',
      labelBgStyle: { fill: 'rgba(15,23,42,0.9)' },
      labelStyle: { fill: e.edge_type === 'EXPLOITS' ? '#f87171' : '#94a3b8' },
    })
  })
  return { nodes, edges }
}

function CustomNode({ data }) {
  const isDanger = data.status === 'takeover' || data.status === 'exposed'
  const isExploit = data.node_type === 'exploit'
  return (
    <div className={`asm-node-inner ${isDanger ? 'pulse' : ''} ${isExploit ? 'asm-exploit-inner' : ''}`}>
      <div className="asm-node-label">{data.label || data.id}</div>
      {data.node_type && <div className="asm-node-type">{data.node_type}{isExploit && data.source ? ` · ${data.source}` : ''}</div>}
      {isExploit && data.status && <div className="asm-node-severity">{data.status}</div>}
    </div>
  )
}

const nodeTypes = { asmNode: CustomNode }

const NS = 'components.tools.attackSurfaceGraph'

export default function AttackSurfaceGraph() {
  const { t } = useTranslation()
  const { clientId } = useParams()

  const remediation = {
    takeover: t(`${NS}.remediation_takeover`),
    exposed: t(`${NS}.remediation_exposed`),
    secure: t(`${NS}.remediation_secure`),
  }
  const [graph, setGraph] = useState({ nodes: [], edges: [], run_id: null, message: '' })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedNode, setSelectedNode] = useState(null)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useEffect(() => {
    if (!clientId) return
    setLoading(true)
    apiFetch(`/api/clients/${clientId}/attack-surface-graph`)
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(t(`${NS}.load_failed`)))))
      .then(data => {
        setGraph(data)
        const { nodes: layoutN, edges: layoutE } = layoutNodes(data.nodes || [], data.edges || [])
        setNodes(layoutN)
        setEdges(layoutE)
      })
      .catch(e => setError(e?.message || t(`${NS}.load_failed`)))
      .finally(() => setLoading(false))
  }, [clientId, setNodes, setEdges, t])

  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node?.data ? { ...node.data, id: node.id } : null)
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-[var(--bg-0)] text-[var(--text-secondary)] flex items-center justify-center">
        <p className="text-cyan-400">{t(`${NS}.loading`)}</p>
      </div>
    )
  }

  return (
    <StandaloneLabShell
      title={t(`${NS}.title`)}
      subtitle={graph.run_id != null ? t(`${NS}.run_id`, { id: graph.run_id }) : undefined}
      contentClassName="p-0"
    >
      {error && (
        <div className="mx-6 mt-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}
      {graph.message && !graph.nodes?.length && (
        <div className="mx-6 mt-4 p-4 rounded bg-[var(--bg-3)]/80 border border-[var(--border-strong)] text-[var(--text-tertiary)] text-sm">
          {graph.message}
        </div>
      )}
      <div className="flex-1 flex" style={{ minHeight: 'calc(100vh - 120px)' }}>
        <div className="flex-1 relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            className="bg-[var(--bg-0)]"
            style={{ background: '#0f172a' }}
          >
            <Background color="#334155" gap={20} />
            <Controls className="bg-[var(--bg-3)]/90 border-[var(--border-strong)]" />
            <MiniMap nodeColor={n => {
              const d = n.data
              if (d?.status === 'takeover') return '#dc2626'
              if (d?.status === 'exposed') return '#f97316'
              return '#0d9488'
            }} className="bg-[var(--bg-3)]/90" />
          </ReactFlow>
        </div>
        {selectedNode && (
          <aside className="w-96 border-l border-[var(--border-default)] bg-[var(--bg-1)]/95 p-4 overflow-y-auto">
            <h3 className="text-sm font-semibold text-[var(--text-secondary)] mb-2">{t(`${NS}.node_details`)}</h3>
            <p className="text-xs text-[var(--text-tertiary)] mb-1">{t(`${NS}.label_id`)} {selectedNode.id}</p>
            <p className="text-sm text-[var(--text-secondary)] mb-2">{selectedNode.label}</p>
            <p className="text-xs text-[var(--text-muted)] mb-2">{t(`${NS}.label_type`)} {selectedNode.node_type} · {t(`${NS}.label_status`)} {selectedNode.status}</p>
            {selectedNode.source && <p className="text-xs text-amber-400 mb-2">{t(`${NS}.label_source`)} {selectedNode.source}</p>}
            {selectedNode.finding_id && <p className="text-xs text-[var(--text-muted)] mb-2">{t(`${NS}.label_finding`)} {selectedNode.finding_id}</p>}
            {selectedNode.cname_target && (
              <p className="text-xs text-cyan-400 mb-2">{t(`${NS}.cname_target`, { target: selectedNode.cname_target })}</p>
            )}
            {selectedNode.raw_finding && (
              <pre className="text-xs bg-[var(--bg-3)] rounded p-2 text-[var(--text-tertiary)] mb-3 overflow-x-auto">
                {JSON.stringify(selectedNode.raw_finding, null, 2)}
              </pre>
            )}
            <h4 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase mb-1">{t(`${NS}.ai_remediation`)}</h4>
            <p className="text-sm text-[var(--text-secondary)]">
              {remediation[selectedNode.status] || remediation.secure}
            </p>
          </aside>
        )}
      </div>
      <style>{`
        .asm-node-inner {
          padding: 8px 14px;
          border-radius: 8px;
          border: 1px solid #475569;
          background: #1e293b;
          min-width: 80px;
          text-align: center;
        }
        .asm-root { --asm-color: #0d9488; }
        .asm-root .asm-node-inner { border-color: #0d9488; background: rgba(13,148,136,0.15); }
        .asm-secure .asm-node-inner { border-color: #475569; color: #94a3b8; }
        .asm-exposed .asm-node-inner { border-color: #f97316; background: rgba(249,115,22,0.2); color: #fdba74; }
        .asm-takeover .asm-node-inner { border-color: #dc2626; background: rgba(220,38,38,0.25); color: #fca5a5; }
        .asm-cloud .asm-node-inner { border-color: #6366f1; background: rgba(99,102,241,0.15); color: #a5b4fc; }
        .asm-exploit .asm-node-inner, .asm-exploit-inner { border-color: #ef4444; background: rgba(239,68,68,0.2); color: #fca5a5; }
        .asm-node-severity { font-size: 9px; text-transform: uppercase; margin-top: 2px; opacity: 0.9; }
        .asm-node-inner.pulse { animation: asm-pulse 1.5s ease-in-out infinite; }
        @keyframes asm-pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(220,38,38,0.4); } 50% { box-shadow: 0 0 0 8px rgba(220,38,38,0); } }
        .asm-node-type { font-size: 10px; opacity: 0.8; margin-top: 2px; }
      `}</style>
    </StandaloneLabShell>
  )
}
