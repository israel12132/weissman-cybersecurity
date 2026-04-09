/**
 * Phase 5: Auto-containment — CISO pre-approved AWS SG swap + K8s NetworkPolicy quarantine.
 */
import React, { useCallback, useEffect, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { ShieldOff, Plus, AlertTriangle, Server, Container } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

export default function ContainmentRulesTab() {
  const { selectedClientId } = useClient()
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(false)
  const [form, setForm] = useState({
    name: '',
    enabled: false,
    pre_approved: false,
    aws_region: '',
    forensic_source_cidr: '10.0.0.0/8',
    forensic_ports_csv: '22,443',
    k8s_api_server: '',
    k8s_token_env_var: '',
    k8s_namespace: 'default',
    k8s_pod_label_key: '',
    k8s_pod_label_value: '',
    allow_dns_egress: true,
  })
  const [exec, setExec] = useState({ rule_id: '', mode: 'aws_sg', aws_instance_id: '' })
  const [msg, setMsg] = useState(null)

  const fetchRules = useCallback(async () => {
    if (!selectedClientId) {
      setRules([])
      return
    }
    setLoading(true)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/containment-rules`)
      const d = await r.json().catch(() => ({}))
      setRules(d.rules || [])
    } catch (_) {
      setRules([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  useEffect(() => {
    fetchRules()
  }, [fetchRules])

  const addRule = async () => {
    if (!selectedClientId || !form.name.trim()) return
    setMsg(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/containment-rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok) {
        setMsg({ ok: true, text: 'Rule saved. Enable + pre-approve before execute.' })
        await fetchRules()
      } else {
        setMsg({ ok: false, text: d.error || r.statusText })
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) })
    }
  }

  const execute = async () => {
    if (!selectedClientId) return
    const rid = parseInt(exec.rule_id, 10)
    if (!Number.isFinite(rid)) {
      setMsg({ ok: false, text: 'Select rule id' })
      return
    }
    setMsg(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/containment/execute`, {
        method: 'POST',
        headers: destructiveHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          rule_id: rid,
          mode: exec.mode,
          aws_instance_id: exec.aws_instance_id || undefined,
          confirm: true,
        }),
      })
      const d = await r.json().catch(() => ({}))
      setMsg({ ok: r.ok, text: d.detail || d.error || JSON.stringify(d) })
    } catch (e) {
      setMsg({ ok: false, text: String(e) })
    }
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        Select a client to configure containment.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <ShieldOff className="w-5 h-5 text-orange-400" />
        <h2 className="text-lg font-semibold text-white">Auto-Containment Rules</h2>
      </div>

      <div className="rounded-xl border border-orange-500/40 bg-orange-500/10 px-4 py-3 flex gap-2 text-orange-200 text-sm">
        <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
        <div>
          <strong>Production impact:</strong> AWS mode replaces the instance security group with a forensic-only group. K8s mode posts a
          deny-by-default <code className="text-orange-100">NetworkPolicy</code>. Requires cross-account IAM (AWS) or API server URL + bearer
          token in an <strong>environment variable</strong> on the engine host (never stored in DB).
        </div>
      </div>

      <div className="rounded-2xl bg-black/40 border border-white/10 p-4 space-y-3">
        <h3 className="text-sm font-medium text-white/90">New rule</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input
            placeholder="Rule name"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder="AWS region (e.g. us-east-1)"
            value={form.aws_region}
            onChange={e => setForm(f => ({ ...f, aws_region: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder="Forensic source CIDR"
            value={form.forensic_source_cidr}
            onChange={e => setForm(f => ({ ...f, forensic_source_cidr: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder="Forensic ports CSV"
            value={form.forensic_ports_csv}
            onChange={e => setForm(f => ({ ...f, forensic_ports_csv: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <label className="flex items-center gap-2 text-sm text-white/80">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
            />
            Enabled
          </label>
          <label className="flex items-center gap-2 text-sm text-white/80">
            <input
              type="checkbox"
              checked={form.pre_approved}
              onChange={e => setForm(f => ({ ...f, pre_approved: e.target.checked }))}
            />
            Pre-approved (required to execute)
          </label>
          <label className="flex items-center gap-2 text-sm text-white/80 md:col-span-2">
            <input
              type="checkbox"
              checked={form.allow_dns_egress}
              onChange={e => setForm(f => ({ ...f, allow_dns_egress: e.target.checked }))}
            />
            Allow UDP/53 egress to WEISSMAN_QUARANTINE_VPC_DNS_CIDR (AWS)
          </label>
          <div className="md:col-span-2 flex items-center gap-2 text-white/50 text-xs">
            <Container className="w-4 h-4" />
            Kubernetes (optional)
          </div>
          <input
            placeholder="K8s API server base URL"
            value={form.k8s_api_server}
            onChange={e => setForm(f => ({ ...f, k8s_api_server: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
          <input
            placeholder="Env var name holding bearer token (e.g. WEISSMAN_K8S_TOKEN)"
            value={form.k8s_token_env_var}
            onChange={e => setForm(f => ({ ...f, k8s_token_env_var: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
          <input
            placeholder="Namespace"
            value={form.k8s_namespace}
            onChange={e => setForm(f => ({ ...f, k8s_namespace: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder="Pod label key"
            value={form.k8s_pod_label_key}
            onChange={e => setForm(f => ({ ...f, k8s_pod_label_key: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder="Pod label value"
            value={form.k8s_pod_label_value}
            onChange={e => setForm(f => ({ ...f, k8s_pod_label_value: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
        </div>
        <button
          type="button"
          onClick={addRule}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-orange-500/50 bg-orange-500/10 text-orange-300"
        >
          <Plus className="w-4 h-4" />
          Save rule
        </button>
      </div>

      <div className="rounded-2xl bg-black/40 border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-2">Execute (incident)</h3>
        <div className="flex flex-wrap gap-2 items-end">
          <select
            value={exec.rule_id}
            onChange={e => setExec(x => ({ ...x, rule_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          >
            <option value="">Rule…</option>
            {rules.map(r => (
              <option key={r.id} value={r.id}>
                #{r.id} {r.name} {r.pre_approved ? '✓' : '—'}
              </option>
            ))}
          </select>
          <select
            value={exec.mode}
            onChange={e => setExec(x => ({ ...x, mode: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          >
            <option value="aws_sg">aws_sg</option>
            <option value="k8s_netpol">k8s_netpol</option>
          </select>
          <input
            placeholder="i-xxxxxxxx (AWS)"
            value={exec.aws_instance_id}
            onChange={e => setExec(x => ({ ...x, aws_instance_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm font-mono"
          />
          <button
            type="button"
            onClick={execute}
            className="px-4 py-2 rounded-xl bg-red-600/80 text-white text-sm hover:bg-red-600"
          >
            Execute quarantine
          </button>
        </div>
      </div>

      {msg && <p className={`text-sm ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`}>{msg.text}</p>}

      <div className="rounded-2xl bg-black/40 border border-white/10 overflow-hidden">
        <div className="px-4 py-2 border-b border-white/10 flex justify-between items-center">
          <span className="text-sm text-white/80">Saved rules</span>
          <button type="button" onClick={fetchRules} className="text-xs text-cyan-400 hover:underline">
            Refresh
          </button>
        </div>
        {loading ? (
          <div className="p-6 text-white/50 text-sm">Loading…</div>
        ) : rules.length === 0 ? (
          <div className="p-6 text-white/50 text-sm">No rules. Create one above.</div>
        ) : (
          <ul className="divide-y divide-white/10">
            {rules.map(r => (
              <li key={r.id} className="p-4 text-sm">
                <div className="flex items-center gap-2 flex-wrap">
                  <Server className="w-4 h-4 text-white/50" />
                  <span className="text-white font-medium">#{r.id} {r.name}</span>
                  <span className={r.enabled ? 'text-emerald-400' : 'text-white/40'}>{r.enabled ? 'on' : 'off'}</span>
                  <span className={r.pre_approved ? 'text-amber-400' : 'text-white/40'}>
                    {r.pre_approved ? 'pre-approved' : 'not approved'}
                  </span>
                </div>
                <div className="mt-1 text-xs text-white/50 font-mono">
                  region={r.aws_region || '—'} cidr={r.forensic_source_cidr} ports={r.forensic_ports_csv}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
