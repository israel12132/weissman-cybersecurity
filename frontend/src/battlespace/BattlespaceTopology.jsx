import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, Network } from 'lucide-react'
import BattlespaceWebGL from './BattlespaceWebGL'
import CommanderIntentHUD from './CommanderIntentHUD'
import ForensicEvidencePanel from './ForensicEvidencePanel'
import { computeIntentMask } from './commanderIntent'
import {
  fetchBattlespaceTopology,
  fetchNodeEvidence,
  fetchShadowPreview,
} from './battlespaceApi'
import { useFirstTenantClientId } from '../lib/aliasClient'

export default function BattlespaceTopology({ connectionStatus = 'online' }) {
  const { t } = useTranslation()
  const { clientId, loading: clientLoading, unavailable: clientsUnavailable } = useFirstTenantClientId()
  const containerRef = useRef(null)
  const workerRef = useRef(null)

  const [topology, setTopology] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [positions, setPositions] = useState(null)
  const [focusNode, setFocusNode] = useState(null)
  const [forensicNode, setForensicNode] = useState(null)
  const [evidence, setEvidence] = useState([])
  const [evidenceError, setEvidenceError] = useState(false)
  const [evidenceTruncated, setEvidenceTruncated] = useState(false)
  const [shadowNodes, setShadowNodes] = useState([])
  const [shadowEdges, setShadowEdges] = useState([])
  const [wargaming, setWargaming] = useState(false)
  const evidenceAbortRef = useRef(null)

  useEffect(() => () => evidenceAbortRef.current?.abort(), [])

  const nodes = useMemo(() => topology?.graph?.nodes || [], [topology])
  const edges = useMemo(() => topology?.graph?.edges || [], [topology])
  const topoKey = `${clientId}-${nodes.length}-${edges.length}`
  const attackPaths = topology?.attack_paths
  const stripsChain = topology?.strips_chain

  const intentMask = useMemo(
    () => computeIntentMask(focusNode?.id, nodes, edges, attackPaths),
    [focusNode?.id, nodes, edges, attackPaths],
  )

  const displayPositions = useMemo(() => {
    if (!positions) return null
    if (!shadowNodes.length) return positions
    const merged = new Float32Array((nodes.length + shadowNodes.length) * 2)
    merged.set(positions.subarray(0, nodes.length * 2))
    const focusIdx = nodes.findIndex((n) => String(n.id) === String(focusNode?.id))
    const fx = focusIdx >= 0 ? positions[focusIdx * 2] : 0
    const fy = focusIdx >= 0 ? positions[focusIdx * 2 + 1] : 0
    shadowNodes.forEach((sn, i) => {
      const angle = (i / Math.max(1, shadowNodes.length)) * Math.PI * 2
      const idx = nodes.length + i
      merged[idx * 2] = fx + Math.cos(angle) * 90
      merged[idx * 2 + 1] = fy + Math.sin(angle) * 90
    })
    return merged
  }, [positions, shadowNodes, nodes, focusNode?.id])

  const normalizedShadowEdges = useMemo(
    () => shadowEdges.map((e) => ({
      ...e,
      source: e.source === 'current_state' ? String(focusNode?.id ?? '') : e.source,
    })),
    [shadowEdges, focusNode?.id],
  )

  useEffect(() => {
    if (clientsUnavailable) {
      setLoading(false)
      setError(null)
      setTopology(null)
      return undefined
    }
    if (!clientId) {
      if (!clientLoading) setLoading(false)
      return undefined
    }
    let cancelled = false
    const ac = new AbortController()
    setLoading(true)
    fetchBattlespaceTopology(clientId, { signal: ac.signal })
      .then((data) => {
        if (!cancelled) {
          setTopology(data)
          setError(null)
        }
      })
      .catch((e) => {
        if (e?.name === 'AbortError' || cancelled) return
        setError(e.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
      ac.abort()
    }
  }, [clientId, clientLoading, clientsUnavailable])

  useEffect(() => {
    if (!nodes.length) return
    const worker = new Worker(new URL('./forceSimulation.worker.js', import.meta.url), { type: 'module' })
    workerRef.current = worker
    worker.onmessage = (ev) => {
      if (ev.data?.type === 'positions') {
        setPositions(new Float32Array(ev.data.positions))
      }
    }
    worker.postMessage({ type: 'init', nodes, edges })
    worker.postMessage({ type: 'start' })
    return () => {
      worker.postMessage({ type: 'stop' })
      worker.terminate()
      workerRef.current = null
    }
  }, [topoKey, nodes, edges])

  const handleNodePick = useCallback(async (node) => {
    if (node.is_shadow) {
      evidenceAbortRef.current?.abort()
      setForensicNode(node)
      setEvidence([])
      setEvidenceError(false)
      setEvidenceTruncated(false)
      return
    }
    setFocusNode(node)
    setForensicNode(node)
    setShadowNodes([])
    setShadowEdges([])
    setEvidence([])
    setEvidenceError(false)
    setEvidenceTruncated(false)
    if (clientId && node.id != null) {
      evidenceAbortRef.current?.abort()
      const ac = new AbortController()
      evidenceAbortRef.current = ac
      const cached = Array.isArray(topology?.open_findings) ? topology.open_findings : undefined
      try {
        const ev = await fetchNodeEvidence(clientId, node.id, {
          signal: ac.signal,
          cachedFindings: cached,
        })
        if (ac.signal.aborted) return
        setEvidence(ev)
        setEvidenceError(false)
        setEvidenceTruncated(Boolean(topology?.open_findings_truncated) && ev.length === 0)
      } catch (e) {
        if (e?.name === 'AbortError' || ac.signal.aborted) return
        setEvidence([])
        setEvidenceError(true)
      }
    }
  }, [clientId, topology])

  const handleWargame = useCallback(async () => {
    if (!clientId) return
    setWargaming(true)
    try {
      const data = await fetchShadowPreview({ clientId })
      setShadowNodes(data.shadow_nodes || [])
      setShadowEdges(data.shadow_edges || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setWargaming(false)
    }
  }, [clientId])

  const isOffline = connectionStatus !== 'online'

  return (
    <div ref={containerRef} className="battlespace-topology relative w-full h-full min-h-[420px] bg-[#030508] overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_80%_60%_at_50%_40%,rgba(34,211,238,0.04),transparent)]" />

      {clientsUnavailable ? (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-6 text-center">
          <p className="text-sm text-amber-200/90" data-testid="battlespace-clients-unavailable" role="alert">
            {t('battlespace.clients_unavailable')}
          </p>
        </div>
      ) : loading || clientLoading ? (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-cyan-300/70">
          <Loader2 className="w-8 h-8 animate-spin" />
          <span className="text-[11px] font-mono uppercase tracking-widest">
            {t('battlespace.loading')}
          </span>
        </div>
      ) : error && !nodes.length ? (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-6 text-center">
          <Network className="w-10 h-10 text-white/20" />
          <p className="text-sm text-white/50">{error}</p>
        </div>
      ) : (
        <>
          <BattlespaceWebGL
            nodes={nodes}
            edges={edges}
            shadowNodes={shadowNodes}
            shadowEdges={normalizedShadowEdges}
            positions={displayPositions}
            intentMask={focusNode ? intentMask : null}
            focusId={focusNode?.id}
            onNodePick={handleNodePick}
          />
          <CommanderIntentHUD
            focusNode={focusNode}
            intentActive={!!focusNode && !!intentMask?.relevantNodes}
            onClearFocus={() => {
              setFocusNode(null)
              setForensicNode(null)
              setShadowNodes([])
              setShadowEdges([])
            }}
            onWargame={handleWargame}
            wargaming={wargaming}
            stripsChain={stripsChain}
            nodeCount={nodes.length + shadowNodes.length}
            edgeCount={edges.length + shadowEdges.length}
          />
          <ForensicEvidencePanel
            node={forensicNode}
            evidence={evidence}
            evidenceError={evidenceError}
            evidenceTruncated={evidenceTruncated}
            onClose={() => setForensicNode(null)}
          />
        </>
      )}

      {isOffline && (
        <div className="absolute inset-0 bg-black/50 flex items-center justify-center z-30">
          <p className="text-[11px] font-mono text-rose-300/90 uppercase tracking-widest">
            {t('battlespace.offline')}
          </p>
        </div>
      )}
    </div>
  )
}
