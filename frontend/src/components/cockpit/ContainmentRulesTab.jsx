/**
 * Phase 5: Auto-containment — CISO pre-approved AWS SG swap + K8s NetworkPolicy quarantine.
 */
import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { ShieldOff, Plus, AlertTriangle, Server, Container } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'

const NS = 'components.cockpitTabs.containmentRules'

export default function ContainmentRulesTab() {
  const { t } = useTranslation()
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
      const d = await apiFetch(`/api/clients/${selectedClientId}/containment-rules`)
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
      await apiFetch(`/api/clients/${selectedClientId}/containment-rules`, {
        method: 'POST',
        body: form,
      })
      setMsg({ ok: true, text: t(`${NS}.ruleSaved`) })
      await fetchRules()
    } catch (e) {
      setMsg({ ok: false, text: e?.status ? e.message : String(e) })
    }
  }

  const execute = async () => {
    if (!selectedClientId) return
    const rid = parseInt(exec.rule_id, 10)
    if (!Number.isFinite(rid)) {
      setMsg({ ok: false, text: t(`${NS}.selectRuleId`) })
      return
    }
    setMsg(null)
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/containment/execute`, {
        method: 'POST',
        headers: destructiveHeaders({ 'Content-Type': 'application/json' }),
        body: {
          rule_id: rid,
          mode: exec.mode,
          aws_instance_id: exec.aws_instance_id || undefined,
          confirm: true,
        },
      })
      setMsg({ ok: true, text: d.detail || d.error || JSON.stringify(d) })
    } catch (e) {
      setMsg({ ok: false, text: e?.status ? e.message : String(e) })
    }
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        {t(`${NS}.selectClient`)}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <ShieldOff className="w-5 h-5 text-orange-400" />
        <h2 className="text-lg font-semibold text-white">{t(`${NS}.title`)}</h2>
      </div>

      <div className="rounded-xl border border-orange-500/40 bg-orange-500/10 px-4 py-3 flex gap-2 text-orange-200 text-sm">
        <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
        <div>
          <strong>{t(`${NS}.productionImpact`)}</strong> {t(`${NS}.productionWarning`)}
        </div>
      </div>

      <div className="rounded-2xl bg-black/40 border border-white/10 p-4 space-y-3">
        <h3 className="text-sm font-medium text-white/90">{t(`${NS}.newRule`)}</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input
            placeholder={t(`${NS}.ruleName`)}
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder={t(`${NS}.awsRegion`)}
            value={form.aws_region}
            onChange={e => setForm(f => ({ ...f, aws_region: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder={t(`${NS}.forensicSourceCidr`)}
            value={form.forensic_source_cidr}
            onChange={e => setForm(f => ({ ...f, forensic_source_cidr: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder={t(`${NS}.forensicPortsCsv`)}
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
            {t(`${NS}.enabled`)}
          </label>
          <label className="flex items-center gap-2 text-sm text-white/80">
            <input
              type="checkbox"
              checked={form.pre_approved}
              onChange={e => setForm(f => ({ ...f, pre_approved: e.target.checked }))}
            />
            {t(`${NS}.preApproved`)}
          </label>
          <label className="flex items-center gap-2 text-sm text-white/80 md:col-span-2">
            <input
              type="checkbox"
              checked={form.allow_dns_egress}
              onChange={e => setForm(f => ({ ...f, allow_dns_egress: e.target.checked }))}
            />
            {t(`${NS}.allowDnsEgress`)}
          </label>
          <div className="md:col-span-2 flex items-center gap-2 text-white/50 text-xs">
            <Container className="w-4 h-4" />
            {t(`${NS}.kubernetesOptional`)}
          </div>
          <input
            placeholder={t(`${NS}.k8sApiServer`)}
            value={form.k8s_api_server}
            onChange={e => setForm(f => ({ ...f, k8s_api_server: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
          <input
            placeholder={t(`${NS}.k8sTokenEnvVar`)}
            value={form.k8s_token_env_var}
            onChange={e => setForm(f => ({ ...f, k8s_token_env_var: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
          <input
            placeholder={t(`${NS}.namespace`)}
            value={form.k8s_namespace}
            onChange={e => setForm(f => ({ ...f, k8s_namespace: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder={t(`${NS}.podLabelKey`)}
            value={form.k8s_pod_label_key}
            onChange={e => setForm(f => ({ ...f, k8s_pod_label_key: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          />
          <input
            placeholder={t(`${NS}.podLabelValue`)}
            value={form.k8s_pod_label_value}
            onChange={e => setForm(f => ({ ...f, k8s_pod_label_value: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm md:col-span-2"
          />
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={addRule}
          className="flex items-center gap-2 px-4 py-2 rounded-xl border border-orange-500/50 bg-orange-500/10 text-orange-300"
        >
          <Plus className="w-4 h-4" />
          {t(`${NS}.saveRule`)}
        </Button>
      </div>

      <div className="rounded-2xl bg-black/40 border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-2">{t(`${NS}.executeTitle`)}</h3>
        <div className="flex flex-wrap gap-2 items-end">
          <select
            value={exec.rule_id}
            onChange={e => setExec(x => ({ ...x, rule_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm"
          >
            <option value="">{t(`${NS}.rulePlaceholder`)}</option>
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
            placeholder={t(`${NS}.awsInstanceId`)}
            value={exec.aws_instance_id}
            onChange={e => setExec(x => ({ ...x, aws_instance_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white text-sm font-mono"
          />
          <Button variant="unstyled"
            type="button"
            onClick={execute}
            className="px-4 py-2 rounded-xl bg-red-600/80 text-white text-sm hover:bg-red-600"
          >
            {t(`${NS}.executeQuarantine`)}
          </Button>
        </div>
      </div>

      {msg && <p className={`text-sm ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`}>{msg.text}</p>}

      <div className="rounded-2xl bg-black/40 border border-white/10 overflow-hidden">
        <div className="px-4 py-2 border-b border-white/10 flex justify-between items-center">
          <span className="text-sm text-white/80">{t(`${NS}.savedRules`)}</span>
          <Button variant="unstyled" type="button" onClick={fetchRules} className="text-xs text-cyan-400 hover:underline">
            {t(`${NS}.refresh`)}
          </Button>
        </div>
        {loading ? (
          <div className="p-6 text-white/50 text-sm">{t(`${NS}.loading`)}</div>
        ) : rules.length === 0 ? (
          <div className="p-6 text-white/50 text-sm">{t(`${NS}.noRules`)}</div>
        ) : (
          <ul className="divide-y divide-white/10">
            {rules.map(r => (
              <li key={r.id} className="p-4 text-sm">
                <div className="flex items-center gap-2 flex-wrap">
                  <Server className="w-4 h-4 text-white/50" />
                  <span className="text-white font-medium">#{r.id} {r.name}</span>
                  <span className={r.enabled ? 'text-emerald-400' : 'text-white/40'}>
                    {r.enabled ? t(`${NS}.on`) : t(`${NS}.off`)}
                  </span>
                  <span className={r.pre_approved ? 'text-amber-400' : 'text-white/40'}>
                    {r.pre_approved ? t(`${NS}.preApprovedStatus`) : t(`${NS}.notApprovedStatus`)}
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
