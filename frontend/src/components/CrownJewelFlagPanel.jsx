import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Crown, Globe } from 'lucide-react'
import { api } from '../utils/apiFetch'
import { withClientId } from '../lib/aliasClient'
import Button from '../components/ui/Button'
import EmptyState from '../components/ui/EmptyState'

const NS = 'pages.attackPaths'

function flagOf(node, key) {
  return Boolean(node?.[key])
}

/**
 * Live operator control for PATCH /api/risk-graph/nodes/:id/flags.
 * Marks internet-exposed entry points and crown jewels so Dijkstra has seeds.
 */
export default function CrownJewelFlagPanel({
  clientId,
  onFlagsChanged,
  compact = false,
}) {
  const { t } = useTranslation()
  const [nodes, setNodes] = useState([])
  const [loading, setLoading] = useState(false)
  const [savingId, setSavingId] = useState(null)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')

  const load = useCallback(async () => {
    if (clientId == null) return
    setLoading(true)
    setError('')
    try {
      const data = await api.get(withClientId('/api/risk/graph', clientId))
      const list = Array.isArray(data?.nodes) ? data.nodes : []
      setNodes(list)
    } catch (e) {
      setError(e.message || t(`${NS}.flags_load_failed`))
      setNodes([])
    } finally {
      setLoading(false)
    }
  }, [clientId, t])

  useEffect(() => {
    load()
  }, [load])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return nodes
    return nodes.filter((n) => {
      const hay = `${n.name || ''} ${n.label || ''} ${n.node_type || ''} ${n.id}`
      return hay.toLowerCase().includes(q)
    })
  }, [nodes, query])

  const jewelCount = nodes.filter((n) => flagOf(n, 'crown_jewel')).length
  const entryCount = nodes.filter((n) => flagOf(n, 'internet_exposed')).length

  const patchFlag = async (node, field, value) => {
    if (node?.id == null) return
    setSavingId(node.id)
    setError('')
    try {
      const res = await api.patch(`/api/risk-graph/nodes/${encodeURIComponent(node.id)}/flags`, {
        [field]: value,
      })
      if (res?.ok === false) throw new Error(res.detail || 'flag patch failed')
      setNodes((prev) =>
        prev.map((n) => (String(n.id) === String(node.id) ? { ...n, [field]: value } : n)),
      )
      if (typeof onFlagsChanged === 'function') {
        await onFlagsChanged({ node, field, value, graphDirty: true })
      }
    } catch (e) {
      setError(e.message || t(`${NS}.flags_save_failed`))
    } finally {
      setSavingId(null)
    }
  }

  if (clientId == null) return null

  return (
    <div
      className="rounded-xl border border-violet-500/30 bg-violet-950/20 p-4 space-y-3"
      data-testid="crown-jewel-flag-panel"
    >
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Crown className="w-4 h-4 text-violet-300" aria-hidden />
            {t(`${NS}.flags_heading`)}
          </h2>
          <p className="text-[11px] text-[var(--text-muted)] mt-1 max-w-xl">
            {t(`${NS}.flags_body`)}
          </p>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span className="px-2 py-0.5 rounded border border-cyan-500/30 text-cyan-200">
            {t(`${NS}.flags_entries_chip`, { count: entryCount })}
          </span>
          <span className="px-2 py-0.5 rounded border border-violet-500/40 text-violet-200">
            {t(`${NS}.flags_jewels_chip`, { count: jewelCount })}
          </span>
        </div>
      </div>

      {error && (
        <div role="alert" className="text-xs font-mono text-rose-300">
          {error}
        </div>
      )}

      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t(`${NS}.flags_search`)}
        className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)]"
        aria-label={t(`${NS}.flags_search`)}
      />

      {loading && nodes.length === 0 ? (
        <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.flags_loading`)}</p>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon="network"
          title={t(`${NS}.flags_empty_title`)}
          body={t(`${NS}.flags_empty_body`)}
        />
      ) : (
        <ul className={`space-y-2 ${compact ? 'max-h-56' : 'max-h-80'} overflow-y-auto`}>
          {filtered.slice(0, 80).map((n) => (
            <li
              key={n.id}
              className="flex items-center justify-between gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] px-3 py-2"
            >
              <div className="min-w-0">
                <div className="text-[12px] text-white truncate">
                  {n.name || n.label || n.graph_key || `#${n.id}`}
                </div>
                <div className="text-[10px] font-mono text-[var(--text-muted)]">
                  {n.node_type || 'node'} · id {n.id}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Button
                  variant="unstyled"
                  type="button"
                  disabled={savingId === n.id}
                  aria-pressed={flagOf(n, 'internet_exposed')}
                  onClick={() => patchFlag(n, 'internet_exposed', !flagOf(n, 'internet_exposed'))}
                  className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-mono border ${
                    flagOf(n, 'internet_exposed')
                      ? 'border-cyan-400/50 bg-cyan-500/20 text-cyan-100'
                      : 'border-[var(--border-default)] text-[var(--text-muted)]'
                  }`}
                >
                  <Globe className="w-3 h-3" aria-hidden />
                  {t(`${NS}.flag_exposed`)}
                </Button>
                <Button
                  variant="unstyled"
                  type="button"
                  disabled={savingId === n.id}
                  aria-pressed={flagOf(n, 'crown_jewel')}
                  onClick={() => patchFlag(n, 'crown_jewel', !flagOf(n, 'crown_jewel'))}
                  className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-mono border ${
                    flagOf(n, 'crown_jewel')
                      ? 'border-violet-400/50 bg-violet-500/20 text-violet-100'
                      : 'border-[var(--border-default)] text-[var(--text-muted)]'
                  }`}
                >
                  <Crown className="w-3 h-3" aria-hidden />
                  {t(`${NS}.flag_jewel`)}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
