import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Crown } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import { useToast } from '../ui/Toaster'
import Switch from '../ui/Switch'
import EmptyState from '../ui/EmptyState'

const NS = 'pages.attackPaths'

/**
 * Operator control to PATCH crown_jewel / internet_exposed on live risk-graph nodes.
 * Dijkstra seeds = internet_exposed, sinks = crown_jewel — without this panel paths stay empty.
 */
export default function CrownJewelBoard({ clientId, onChanged, onInventory }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [nodes, setNodes] = useState([])
  const [loading, setLoading] = useState(() => clientId != null)
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    if (clientId == null) {
      setNodes([])
      setError('')
      return undefined
    }
    setLoading(true)
    setError('')
    setNodes([])
    apiFetch(`/api/clients/${encodeURIComponent(clientId)}/risk-graph`)
      .then((data) => {
        if (cancelled) return
        if (data?.unavailable || data?.ok === false) throw new Error(t(`${NS}.jewel_load_failed`))
        setNodes(Array.isArray(data?.nodes) ? data.nodes : [])
      })
      .catch((e) => {
        if (cancelled) return
        setError(e.message || t(`${NS}.jewel_load_failed`))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [clientId])

  const jewelCount = useMemo(
    () => nodes.filter((n) => n.crown_jewel).length,
    [nodes],
  )
  const exposedCount = useMemo(
    () => nodes.filter((n) => n.internet_exposed).length,
    [nodes],
  )

  useEffect(() => {
    const unknown = Boolean(error) || loading
    onInventory?.({
      total: unknown ? null : nodes.length,
      jewels: unknown ? null : jewelCount,
      exposed: unknown ? null : exposedCount,
      loading,
      unavailable: Boolean(error),
    })
  }, [nodes.length, jewelCount, exposedCount, loading, error, onInventory])

  const toggle = useCallback(
    async (nodeId, field, next) => {
      setBusyId(nodeId)
      setError('')
      try {
        const data = await apiFetch(`/api/risk-graph/nodes/${encodeURIComponent(nodeId)}/flags`, {
          method: 'PATCH',
          body: { [field]: Boolean(next) },
        })
        if (data?.ok === false) throw new Error(data.detail || t(`${NS}.jewel_save_failed`))
        setNodes((prev) =>
          prev.map((n) => (Number(n.id) === Number(nodeId) ? { ...n, [field]: Boolean(next) } : n)),
        )
        toast.success(t(`${NS}.jewel_save_ok`))
        onChanged?.()
      } catch (e) {
        toast.error(e.message || t(`${NS}.jewel_save_failed`))
      } finally {
        setBusyId(null)
      }
    },
    [onChanged, t, toast],
  )

  if (clientId == null) return null

  return (
    <div
      data-testid="crown-jewel-board"
      className="rounded-xl border border-amber-500/30 bg-gradient-to-br from-amber-950/30 via-[var(--table-surface)] to-violet-950/20 p-4 space-y-3"
    >
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-amber-200/90 flex items-center gap-2">
            <Crown className="w-3.5 h-3.5" aria-hidden />
            {t(`${NS}.jewel_panel_title`)}
          </h2>
          <p className="text-[11px] text-[var(--text-muted)] mt-1 max-w-2xl">
            {t(`${NS}.jewel_panel_hint`)}
          </p>
        </div>
        {!error && (
          <span className="text-[10px] font-mono text-amber-200/80">
            {t(`${NS}.jewel_marked`, { count: jewelCount, total: nodes.length })}
          </span>
        )}
      </div>

      {error && (
        <div
          role="alert"
          data-testid="crown-jewel-unavailable"
          className="text-[11px] font-mono text-rose-300"
        >
          {error}
        </div>
      )}

      {loading && (
        <p className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.jewel_loading`)}</p>
      )}

      {!loading && !error && nodes.length === 0 && (
        <EmptyState
          icon="network"
          title={t(`${NS}.jewel_empty_title`)}
          body={t(`${NS}.jewel_empty_body`)}
        />
      )}

      {!loading && nodes.length > 0 && (
        <ul className="divide-y divide-[var(--border-subtle)] max-h-72 overflow-y-auto">
          {nodes.map((n) => (
            <li
              key={n.id}
              className="flex items-center gap-3 py-2 flex-wrap"
              data-testid={`jewel-row-${n.id}`}
            >
              <div className="min-w-0 flex-1">
                <p className="text-[12px] text-[var(--text-primary)] truncate" title={n.label || n.graph_key}>
                  {n.label || n.graph_key || `#${n.id}`}
                </p>
                <p className="text-[10px] font-mono text-[var(--text-muted)]">
                  {t(`${NS}.jewel_node_meta`, {
                    type: n.node_type || t(`${NS}.jewel_node_fallback`),
                    score: Number(n.risk_score) || 0,
                  })}
                </p>
              </div>
              <Switch
                size="sm"
                data-testid={`jewel-toggle-exposed-${n.id}`}
                checked={Boolean(n.internet_exposed)}
                disabled={busyId != null && Number(busyId) === Number(n.id)}
                onChange={(e) => toggle(n.id, 'internet_exposed', e.target.checked)}
                label={t(`${NS}.toggle_internet_exposed`)}
              />
              <Switch
                size="sm"
                data-testid={`jewel-toggle-crown-${n.id}`}
                checked={Boolean(n.crown_jewel)}
                disabled={busyId != null && Number(busyId) === Number(n.id)}
                onChange={(e) => toggle(n.id, 'crown_jewel', e.target.checked)}
                label={t(`${NS}.toggle_crown_jewel`)}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
