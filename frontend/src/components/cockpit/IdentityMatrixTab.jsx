import React, { useState, useEffect, useCallback } from 'react'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { motion } from 'framer-motion'
import { ShieldAlert, UserPlus, Trash2, ArrowRight, Zap, Sparkles } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

export default function IdentityMatrixTab() {
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
      const r = await apiFetch(`/api/clients/${selectedClientId}/identity-contexts`)
      if (r.ok) {
        const d = await r.json()
        setContexts(d.contexts || [])
      }
    } catch (_) {}
  }, [selectedClientId])

  const fetchEvents = useCallback(async () => {
    if (!selectedClientId) return
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/privilege-escalation`)
      if (r.ok) {
        const d = await r.json()
        setEvents(d.events || [])
      }
    } catch (_) {}
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
    const t = setInterval(() => {
      fetchEvents()
    }, 4000)
    return () => clearInterval(t)
  }, [polling, selectedClientId, fetchEvents])

  useEffect(() => {
    if (!lastHarvestedToken || String(lastHarvestedToken.client_id) !== String(selectedClientId)) return
    setHarvestAlert(true)
    fetchContexts().then(() => {
      setLastHarvestedToken?.(null)
    })
    const t = setTimeout(() => setHarvestAlert(false), 8000)
    return () => clearTimeout(t)
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
      const r = await apiFetch(`/api/clients/${selectedClientId}/identity-contexts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          role_name: form.role_name.trim(),
          privilege_order: Number(form.privilege_order) || 0,
          token_type: form.token_type,
          token_value: form.token_value,
        }),
      })
      if (r.ok) {
        setForm({ role_name: '', privilege_order: 0, token_type: 'bearer', token_value: '' })
        await fetchContexts()
      }
    } catch (_) {}
    setSubmitting(false)
  }

  const handleDelete = async (ctxId) => {
    if (!selectedClientId) return
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/identity-contexts/${ctxId}`, {
        method: 'DELETE',
      })
      if (r.ok) await fetchContexts()
    } catch (_) {}
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <p className="text-sm text-white/70">Select a client to manage Identity Matrix.</p>
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
            <p className="font-medium text-amber-200">High-Privilege token auto-harvested</p>
            <p className="text-xs text-amber-200/80">Backend escalated privileges; new context added to the table. Shadow Replay will use it on next run.</p>
          </div>
        </motion.div>
      )}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2 text-white/90">
          <ShieldAlert className="w-5 h-5 text-amber-500" />
          <h2 className="text-lg font-semibold tracking-wide">Identity Matrix</h2>
          <span className="text-xs text-white/50">Multi-role tokens for Shadow Replay & privilege escalation</span>
        </div>
        <label className="flex items-center gap-2 ml-auto cursor-pointer">
          <span className="text-sm text-white/70">Auto-Harvest</span>
          <button
            type="button"
            role="switch"
            aria-checked={autoHarvest}
            onClick={toggleAutoHarvest}
            className={`relative w-11 h-6 rounded-full transition-colors ${autoHarvest ? 'bg-amber-500/60' : 'bg-white/20'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${autoHarvest ? 'translate-x-5' : 'translate-x-0'}`} />
          </button>
          <span className="text-xs text-white/50">{autoHarvest ? 'ON' : 'OFF'}</span>
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
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">Role name</label>
            <input
              type="text"
              value={form.role_name}
              onChange={(e) => setForm((f) => ({ ...f, role_name: e.target.value }))}
              placeholder="Admin / User / Guest"
              className="w-40 rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white placeholder-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">Privilege order (higher = more privileged)</label>
            <input
              type="number"
              value={form.privilege_order}
              onChange={(e) => setForm((f) => ({ ...f, privilege_order: parseInt(e.target.value, 10) || 0 }))}
              className="w-24 rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">Token type</label>
            <select
              value={form.token_type}
              onChange={(e) => setForm((f) => ({ ...f, token_type: e.target.value }))}
              className="rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white focus:border-[#22d3ee]/50 focus:outline-none"
            >
              <option value="bearer">Bearer</option>
              <option value="cookie">Cookie</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[10px] uppercase tracking-wider text-white/50 mb-1">Token value</label>
            <input
              type="password"
              value={form.token_value}
              onChange={(e) => setForm((f) => ({ ...f, token_value: e.target.value }))}
              placeholder={form.token_type === 'cookie' ? 'session=…; auth=…' : 'JWT or Bearer token'}
              className="w-full rounded-lg border border-white/20 bg-black/60 px-3 py-2 text-sm text-white placeholder-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={submitting || !form.role_name.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 disabled:opacity-50"
          >
            <UserPlus className="w-4 h-4" /> Add context
          </button>
        </div>
      </motion.form>

      {/* Current contexts table */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider text-white/50">Session contexts ({contexts.length})</span>
          {contexts.length >= 2 && (
            <button
              type="button"
              onClick={() => setPolling((p) => !p)}
              className={`text-xs px-2 py-1 rounded ${polling ? 'bg-amber-500/20 text-amber-400' : 'text-white/50 hover:text-white/70'}`}
            >
              {polling ? 'Live updates ON' : 'Enable live updates'}
            </button>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/5">
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-white/50">Role</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-white/50">Privilege order</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-white/50">Token type</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-white/50">Token</th>
                <th className="w-20" />
              </tr>
            </thead>
            <tbody>
              {contexts.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-white/50">
                    Add at least two contexts (e.g. Admin, User) to run Shadow Replay. Run ENGAGE TARGET to trigger BOLA + identity tests.
                  </td>
                </tr>
              )}
              {contexts.map((ctx) => (
                <tr key={ctx.id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="py-3 px-4 font-medium text-white/90">{ctx.role_name}</td>
                  <td className="py-3 px-4 text-white/70">{ctx.privilege_order}</td>
                  <td className="py-3 px-4 text-white/70">{ctx.token_type}</td>
                  <td className="py-3 px-4 font-mono text-[10px] text-white/50">{ctx.token_masked || '—'}</td>
                  <td className="py-3 px-4">
                    <button
                      type="button"
                      onClick={() => handleDelete(ctx.id)}
                      className="p-1.5 rounded text-red-400/80 hover:bg-red-500/20 hover:text-red-400"
                      aria-label="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Privilege Escalation Graph */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-500" />
          <span className="text-sm font-medium text-white/90">Privilege Escalation (Kill Chain)</span>
          <span className="text-xs text-white/50">— low-priv context executed high-priv action</span>
        </div>
        <div className="p-4">
          {events.length === 0 ? (
            <p className="text-sm text-white/50 py-6 text-center">
              No privilege escalation events yet. Add contexts, run ENGAGE TARGET; Shadow Engine will record when a lower-privilege token succeeds on an admin path.
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
