import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'
import DataTable from '../ui/DataTable'

const NS = 'components.cockpitTabs.aiModelRisk'
const columnHelper = createColumnHelper()

export default function AIModelRiskTab() {
  const { t } = useTranslation()
  const { selectedClientId, selectedClient } = useClient()
  const [summary, setSummary] = useState({ vectors: [] })
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState(null)
  const [endpoints, setEndpoints] = useState([{ url: '', model: '', authorization: '' }])

  const vectorLabel = (key) => t(`${NS}.vectors.${key}`, key)

  const eventColumns = useMemo(
    () => [
      columnHelper.accessor('attack_vector', {
        header: t(`${NS}.colVector`),
        cell: (info) => (
          <span className="text-violet-300 font-mono max-w-[140px] truncate block" title={info.getValue()}>
            {t(`${NS}.vectors.${info.getValue()}`, info.getValue())}
          </span>
        ),
      }),
      columnHelper.accessor('endpoint_url', {
        header: t(`${NS}.colEndpoint`),
        cell: (info) => (
          <span className="text-white/70 font-mono max-w-[200px] truncate block" title={info.getValue()}>
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor((e) => e.leakage_score ?? 0, {
        id: 'leakage_score',
        header: t(`${NS}.colLeak`),
        cell: (info) => <span className="text-red-300">{Number(info.getValue()).toFixed(2)}</span>,
      }),
      columnHelper.accessor((e) => e.hallucination_score ?? 0, {
        id: 'hallucination_score',
        header: t(`${NS}.colHalluc`),
        cell: (info) => <span className="text-amber-300">{Number(info.getValue()).toFixed(2)}</span>,
      }),
      columnHelper.accessor((e) => Boolean(e.blocked), {
        id: 'blocked',
        header: t(`${NS}.colBlocked`),
        cell: (info) => <span>{info.getValue() ? t(`${NS}.blockedYes`) : '—'}</span>,
      }),
    ],
    [t],
  )

  const loadEndpoints = useCallback(async () => {
    if (!selectedClientId) return
    let d
    try {
      d = await apiFetch(`/api/clients/${selectedClientId}/integrations`)
    } catch (e) {
      if (e?.status) return
      throw e
    }
    const eps = Array.isArray(d.llm_secops_endpoints) && d.llm_secops_endpoints.length
      ? d.llm_secops_endpoints.map((e) => ({
          url: e.url || '',
          model: e.model || '',
          authorization: e.authorization?.configured ? '••••••••' : '',
        }))
      : [{ url: '', model: '', authorization: '' }]
    setEndpoints(eps)
  }, [selectedClientId])

  const load = useCallback(async () => {
    if (!selectedClientId) return
    setLoading(true)
    setMsg(null)
    try {
      await loadEndpoints()
      const [sRes, eRes] = await Promise.all([
        apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/summary`).catch(() => null),
        apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/events`).catch(() => null),
      ])
      if (sRes) {
        setSummary({ vectors: sRes.vectors ?? [] })
      } else {
        setSummary({ vectors: [] })
      }
      if (eRes) {
        setEvents(eRes.events ?? [])
      } else {
        setEvents([])
      }
    } catch (_) {
      setSummary({ vectors: [] })
      setEvents([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, loadEndpoints])

  useEffect(() => {
    load()
  }, [load])

  const saveEndpoints = async () => {
    if (!selectedClientId) return
    setSaving(true)
    setMsg(null)
    try {
      const llm_secops_endpoints = endpoints
        .filter((e) => e.url.trim())
        .map((e) => ({
          url: e.url.trim(),
          model: e.model.trim() || undefined,
          authorization: e.authorization.trim() || undefined,
        }))
      await apiFetch(`/api/clients/${selectedClientId}/integrations`, {
        method: 'PATCH',
        body: { llm_secops_endpoints },
      })
      setMsg({ type: 'ok', text: t(`${NS}.endpointsSaved`) })
      await loadEndpoints()
    } catch (e) {
      setMsg({ type: 'err', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  const runFuzz = async () => {
    if (!selectedClientId) return
    setRunning(true)
    setMsg(null)
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/run`, {
        method: 'POST',
      })
      setMsg({ type: 'ok', text: t(`${NS}.probesCompleted`, { count: d.summary?.probes?.length ?? 0 }) })
      await load()
    } catch (e) {
      if (e?.status) {
        const d = e.response ? await e.response.json().catch(() => ({})) : {}
        setMsg({ type: 'err', text: d.detail || d.error || t(`${NS}.runFailed`) })
      } else {
        setMsg({ type: 'err', text: String(e.message || e) })
      }
    } finally {
      setRunning(false)
    }
  }

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">{t(`${NS}.selectClient`)}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-8 max-w-6xl">
      <div className="rounded-2xl bg-gradient-to-br from-violet-950/40 to-black/60 border border-violet-500/30 p-6">
        <h2 className="text-lg font-semibold text-white mb-1">{t(`${NS}.title`)}</h2>
        <p className="text-sm text-white/60 mb-4">{t(`${NS}.descriptionSecure`)}</p>

        <div className="space-y-3 mb-4">
          {endpoints.map((ep, i) => (
            <div key={i} className="grid md:grid-cols-12 gap-2 p-3 rounded-xl border border-white/10 bg-black/40">
              <input
                className="md:col-span-5 px-3 py-2 rounded-lg bg-black/50 border border-white/10 text-sm text-white font-mono"
                placeholder="https://api.example.com/v1/chat/completions"
                value={ep.url}
                onChange={(e) => {
                  const next = [...endpoints]
                  next[i] = { ...next[i], url: e.target.value }
                  setEndpoints(next)
                }}
              />
              <input
                className="md:col-span-3 px-3 py-2 rounded-lg bg-black/50 border border-white/10 text-sm text-white"
                placeholder="gpt-4o-mini"
                value={ep.model}
                onChange={(e) => {
                  const next = [...endpoints]
                  next[i] = { ...next[i], model: e.target.value }
                  setEndpoints(next)
                }}
              />
              <input
                type="password"
                autoComplete="off"
                className="md:col-span-4 px-3 py-2 rounded-lg bg-black/50 border border-white/10 text-sm text-white font-mono"
                placeholder="Bearer sk-…"
                value={ep.authorization}
                onChange={(e) => {
                  const next = [...endpoints]
                  next[i] = { ...next[i], authorization: e.target.value }
                  setEndpoints(next)
                }}
              />
            </div>
          ))}
          <div className="flex flex-wrap gap-2">
            <Button variant="unstyled" type="button" className="text-xs text-violet-300" onClick={() => setEndpoints([...endpoints, { url: '', model: '', authorization: '' }])}>
              + {t(`${NS}.addEndpoint`)}
            </Button>
            <Link to={`/clients/${selectedClientId}/integrations`} className="text-xs text-cyan-400">
              {t(`${NS}.fullIntegrations`)}
            </Link>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <Button variant="unstyled"
            type="button"
            disabled={saving}
            onClick={saveEndpoints}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-violet-500/40 bg-violet-600/20 text-violet-100 hover:bg-violet-600/30 disabled:opacity-40"
          >
            {saving ? t(`${NS}.saving`) : t(`${NS}.saveEndpoints`)}
          </Button>
          <Button variant="unstyled"
            type="button"
            disabled={running || !selectedClientId}
            onClick={runFuzz}
            className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-violet-500/50 bg-violet-600/20 text-violet-200 hover:bg-violet-600/30 disabled:opacity-40"
          >
            {running ? t(`${NS}.runningProbes`) : t(`${NS}.runSuite`)}
          </Button>
        </div>
        {msg && (
          <p className={`mt-3 text-sm ${msg.type === 'ok' ? 'text-emerald-400' : 'text-red-400'}`}>{msg.text}</p>
        )}
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6">
        <h3 className="text-xs font-mono uppercase tracking-wider text-violet-400 mb-4">{t(`${NS}.attackVectorsTitle`)}</h3>
        {loading && <p className="text-white/50 text-sm">{t(`${NS}.loading`)}</p>}
        {!loading && (!summary.vectors || summary.vectors.length === 0) && (
          <p className="text-white/50 text-sm">{t(`${NS}.noTelemetry`)}</p>
        )}
        <div className="space-y-4">
          {(summary.vectors || []).map((v) => {
            const label = vectorLabel(v.attack_vector)
            const leak = Math.min(100, (v.avg_leakage || 0) * 100)
            const hall = Math.min(100, (v.avg_hallucination_under_duress || 0) * 100)
            return (
              <div key={v.attack_vector} className="space-y-1">
                <div className="flex justify-between text-xs text-white/80">
                  <span>{label}</span>
                  <span className="text-white/40">{t(`${NS}.samples`, { count: v.sample_count })}</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <div className="text-[10px] text-red-400/90 mb-0.5">{t(`${NS}.leakageScore`)}</div>
                    <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                      <div className="h-full rounded-full bg-gradient-to-r from-red-600 to-orange-500 transition-all" style={{ width: `${leak}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-amber-400/90 mb-0.5">{t(`${NS}.hallucinationDuress`)}</div>
                    <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                      <div className="h-full rounded-full bg-gradient-to-r from-amber-600 to-yellow-400 transition-all" style={{ width: `${hall}%` }} />
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400">{t(`${NS}.recentEvents`)}</h3>
        </div>
        <DataTable
          id="ai-model-risk-events-table"
          columns={eventColumns}
          data={events}
          loading={loading}
          getRowId={(e) => e.id}
          animateRows={false}
          emptyState={<span className="text-white/40">{t(`${NS}.noEvents`)}</span>}
        />
      </div>
    </div>
  )
}
