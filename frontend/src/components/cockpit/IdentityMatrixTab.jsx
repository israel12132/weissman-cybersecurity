import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { motion } from 'framer-motion'
import { ShieldAlert, UserPlus, Trash2, ArrowRight, Zap, Sparkles } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'
import DataTable from '../ui/DataTable'

const columnHelper = createColumnHelper()
const IM = 'components.cockpitTabs.identityMatrix'

export default function IdentityMatrixTab() {
  const { t } = useTranslation()
  const { selectedClientId, clientConfig, patchConfig } = useClient()
  const { lastHarvestedToken, setLastHarvestedToken } = useWarRoom()
  const [contexts, setContexts] = useState([])
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ role_name: '', privilege_order: 0, token_type: 'bearer', token_value: '' })
  const [submitting, setSubmitting] = useState(false)
  const [polling, setPolling] = useState(false)
  const [harvestAlert, setHarvestAlert] = useState(false)

  const fetchContexts = useCallback(async () => {
    if (!selectedClientId) return
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/identity-contexts`)
      setContexts(d.contexts || [])
    } catch (_) { /* best-effort; non-fatal */ }
  }, [selectedClientId])

  const fetchEvents = useCallback(async () => {
    if (!selectedClientId) return
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/privilege-escalation`)
      setEvents(d.events || [])
    } catch (_) { /* best-effort; non-fatal */ }
  }, [selectedClientId])

  useEffect(() => {
    if (!selectedClientId) {
      setContexts([])
      setEvents([])
      setLoading(false)
      return
    }
    setLoading(true)
    Promise.all([fetchContexts(), fetchEvents()]).finally(() => setLoading(false))
  }, [selectedClientId, fetchContexts, fetchEvents])

  useEffect(() => {
    if (!polling || !selectedClientId) return
    const timer = setInterval(() => {
      fetchEvents()
    }, 4000)
    return () => clearInterval(timer)
  }, [polling, selectedClientId, fetchEvents])

  useEffect(() => {
    if (!lastHarvestedToken || String(lastHarvestedToken.client_id) !== String(selectedClientId)) return
    setHarvestAlert(true)
    fetchContexts().then(() => {
      setLastHarvestedToken?.(null)
    })
    const timeout = setTimeout(() => setHarvestAlert(false), 8000)
    return () => clearTimeout(timeout)
  }, [lastHarvestedToken, selectedClientId, fetchContexts, setLastHarvestedToken])

  const autoHarvest = clientConfig?.auto_harvest !== false
  const toggleAutoHarvest = useCallback(async () => {
    if (selectedClientId) await patchConfig({ auto_harvest: !autoHarvest })
  }, [selectedClientId, patchConfig, autoHarvest])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!selectedClientId || !form.role_name.trim()) return
    setSubmitting(true)
    try {
      await apiFetch(`/api/clients/${selectedClientId}/identity-contexts`, {
        method: 'POST',
        body: {
          role_name: form.role_name.trim(),
          privilege_order: Number(form.privilege_order) || 0,
          token_type: form.token_type,
          token_value: form.token_value,
        },
      })
      setForm({ role_name: '', privilege_order: 0, token_type: 'bearer', token_value: '' })
      await fetchContexts()
    } catch (_) { /* best-effort; non-fatal */ }
    setSubmitting(false)
  }

  const handleDelete = useCallback(
    async (ctxId) => {
      if (!selectedClientId) return
      try {
        await apiFetch(`/api/clients/${selectedClientId}/identity-contexts/${ctxId}`, {
          method: 'DELETE',
        })
        await fetchContexts()
      } catch (_) { /* best-effort; non-fatal */ }
    },
    [selectedClientId, fetchContexts],
  )

  const contextColumns = useMemo(
    () => [
      columnHelper.accessor('role_name', {
        header: t(`${IM}.table.role`),
        cell: (info) => <span className="font-medium text-white/90">{info.getValue()}</span>,
      }),
      columnHelper.accessor('privilege_order', {
        header: t(`${IM}.table.privilege_order`),
        cell: (info) => <span className="text-white/70">{info.getValue()}</span>,
      }),
      columnHelper.accessor('token_type', {
        header: t(`${IM}.table.token_type`),
        cell: (info) => <span className="text-white/70">{info.getValue()}</span>,
      }),
      columnHelper.accessor((c) => c.token_masked || '—', {
        id: 'token_masked',
        header: t(`${IM}.table.token`),
        cell: (info) => <span className="font-mono text-[10px] text-white/50">{info.getValue()}</span>,
      }),
      columnHelper.display({
        id: 'delete',
        header: '',
        cell: ({ row }) => (
          <Button
            variant="unstyled"
            type="button"
            onClick={() => handleDelete(row.original.id)}
            className="p-1.5 rounded text-red-400/80 hover:bg-red-500/20 hover:text-red-400"
            aria-label={t(`${IM}.delete`)}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        ),
      }),
    ],
    [t, handleDelete],
  )

  if (!selectedClientId) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <p className="text-sm text-white/70">{t('components.cockpitTabs.identityMatrix.select_client')}</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-[#22d3ee]/50 border-t-[#22d3ee]" />
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-8">
      {harvestAlert && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-amber-500/50 bg-amber-500/20 px-4 py-3 flex items-center gap-3"
        >
          <Sparkles className="w-5 h-5 text-amber-400 shrink-0" />
          <div>
            <p className="font-medium text-amber-200">{t('components.cockpitTabs.identityMatrix.harvest_alert_title')}</p>
            <p className="text-xs text-amber-200/80">{t('components.cockpitTabs.identityMatrix.harvest_alert_body')}</p>
          </div>
        </motion.div>
      )}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2 text-white/90">
          <ShieldAlert className="w-5 h-5 text-amber-500" />
          <h2 className="text-lg font-semibold tracking-wide">{t('components.cockpitTabs.identityMatrix.title')}</h2>
          <span className="text-xs text-white/50">{t('components.cockpitTabs.identityMatrix.subtitle')}</span>
        </div>
        <label className="flex items-center gap-2 ml-auto cursor-pointer">
          <span className="text-sm text-white/70">{t('components.cockpitTabs.identityMatrix.auto_harvest')}</span>
          <Button variant="unstyled"
            type="button"
            role="switch"
            aria-checked={autoHarvest}
            onClick={toggleAutoHarvest}
            className={`relative w-11 h-6 rounded-full transition-colors ${autoHarvest ? 'bg-amber-500/60' : 'bg-white/20'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${autoHarvest ? 'translate-x-5' : 'translate-x-0'}`} />
          </Button>
          <span className="text-xs text-white/50">
            {autoHarvest ? t('components.cockpitTabs.identityMatrix.on') : t('components.cockpitTabs.identityMatrix.off')}
          </span>
        </label>
      </div>

      {/* Add context form */}
      <motion.form
        onSubmit={handleAdd}
        className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">
              {t('components.cockpitTabs.identityMatrix.form.role_name')}
            </label>
            <input
              type="text"
              value={form.role_name}
              onChange={(e) => setForm((f) => ({ ...f, role_name: e.target.value }))}
              placeholder={t('components.cockpitTabs.identityMatrix.form.role_placeholder')}
              className="w-40 rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white placeholder-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">
              {t('components.cockpitTabs.identityMatrix.form.privilege_order')}
            </label>
            <input
              type="number"
              value={form.privilege_order}
              onChange={(e) => setForm((f) => ({ ...f, privilege_order: parseInt(e.target.value, 10) || 0 }))}
              className="w-24 rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">
              {t('components.cockpitTabs.identityMatrix.form.token_type')}
            </label>
            <select
              value={form.token_type}
              onChange={(e) => setForm((f) => ({ ...f, token_type: e.target.value }))}
              className="rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white focus:border-[#22d3ee]/50 focus:outline-none"
            >
              <option value="bearer">{t('components.cockpitTabs.identityMatrix.form.bearer')}</option>
              <option value="cookie">{t('components.cockpitTabs.identityMatrix.form.cookie')}</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">
              {t('components.cockpitTabs.identityMatrix.form.token_value')}
            </label>
            <input
              type="password"
              value={form.token_value}
              onChange={(e) => setForm((f) => ({ ...f, token_value: e.target.value }))}
              placeholder={
                form.token_type === 'cookie'
                  ? t('components.cockpitTabs.identityMatrix.form.token_placeholder_cookie')
                  : t('components.cockpitTabs.identityMatrix.form.token_placeholder_bearer')
              }
              className="w-full rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white placeholder-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <Button variant="unstyled"
            type="submit"
            disabled={submitting || !form.role_name.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 disabled:opacity-50"
          >
            <UserPlus className="w-4 h-4" /> {t('components.cockpitTabs.identityMatrix.add_context')}
          </Button>
        </div>
      </motion.form>

      {/* Current contexts table */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider text-white/50">
            {t('components.cockpitTabs.identityMatrix.session_contexts', { count: contexts.length })}
          </span>
          {contexts.length >= 2 && (
            <Button variant="unstyled"
              type="button"
              onClick={() => setPolling((p) => !p)}
              className={`text-xs px-2 py-1 rounded ${polling ? 'bg-amber-500/20 text-amber-400' : 'text-white/50 hover:text-white/70'}`}
            >
              {polling
                ? t('components.cockpitTabs.identityMatrix.live_updates_on')
                : t('components.cockpitTabs.identityMatrix.enable_live_updates')}
            </Button>
          )}
        </div>
        <DataTable
          id="identity-matrix-contexts-table"
          columns={contextColumns}
          data={contexts}
          getRowId={(c) => c.id}
          animateRows={false}
          emptyState={<span className="text-white/50">{t(`${IM}.empty_contexts`)}</span>}
        />
      </div>

      {/* Privilege Escalation Graph */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-500" />
          <span className="text-sm font-medium text-white/90">
            {t('components.cockpitTabs.identityMatrix.escalation.title')}
          </span>
          <span className="text-xs text-white/50">
            {t('components.cockpitTabs.identityMatrix.escalation.subtitle')}
          </span>
        </div>
        <div className="p-4">
          {events.length === 0 ? (
            <p className="text-sm text-white/50 py-6 text-center">
              {t('components.cockpitTabs.identityMatrix.escalation.empty')}
            </p>
          ) : (
            <div className="space-y-3">
              {events.slice(0, 50).map((ev) => (
                <motion.div
                  key={ev.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-950/20 px-4 py-3"
                >
                  <span className="font-medium text-white/90 min-w-[80px]">{ev.from_context}</span>
                  <ArrowRight className="w-4 h-4 text-red-400/80 shrink-0" />
                  <span className="font-medium text-red-400 min-w-[80px]">{ev.to_context}</span>
                  <span className="text-xs text-white/50 truncate flex-1" title={ev.url}>
                    {ev.method} {ev.url}
                  </span>
                  {ev.response_status != null && (
                    <span className="text-xs font-mono text-white/60">{ev.response_status}</span>
                  )}
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
