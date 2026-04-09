import React, { useCallback, useEffect, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../lib/apiBase'

function labelForFramework(fw) {
  if (fw === 'SOC2') return 'SOC 2'
  if (fw === 'ISO27001') return 'ISO 27001'
  if (fw === 'GDPR') return 'GDPR'
  return fw
}

export default function ComplianceDashboardTab() {
  const { selectedClient, selectedClientId, refreshClients } = useClient()
  const [arn, setArn] = useState('')
  const [externalId, setExternalId] = useState('')
  const [gcpProject, setGcpProject] = useState('')
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [msg, setMsg] = useState(null)
  const [posture, setPosture] = useState(null)
  const [postureLoading, setPostureLoading] = useState(true)

  useEffect(() => {
    if (!selectedClient) {
      setArn('')
      setExternalId('')
      setGcpProject('')
      return
    }
    setArn(selectedClient.aws_cross_account_role_arn || '')
    setExternalId(selectedClient.aws_external_id || '')
    setGcpProject(selectedClient.gcp_project_id || '')
  }, [selectedClient])

  const loadPosture = useCallback(() => {
    if (!selectedClientId) {
      setPosture(null)
      setPostureLoading(false)
      return
    }
    setPostureLoading(true)
    const q = `?client_id=${encodeURIComponent(selectedClientId)}`
    apiFetch(`/api/compliance/posture${q}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setPosture(d))
      .catch(() => setPosture(null))
      .finally(() => setPostureLoading(false))
  }, [selectedClientId])

  useEffect(() => {
    loadPosture()
  }, [loadPosture])

  const saveCloudIntegration = async () => {
    if (!selectedClientId) return
    setSaving(true)
    setMsg(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/cloud-integration`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          aws_cross_account_role_arn: arn.trim(),
          aws_external_id: externalId.trim(),
          gcp_project_id: gcpProject.trim(),
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok) {
        setMsg({ type: 'ok', text: 'Cloud integration saved. Trust policy on the role must allow this platform principal.' })
        refreshClients()
      } else {
        setMsg({ type: 'err', text: d.detail || 'Save failed' })
      }
    } catch {
      setMsg({ type: 'err', text: 'Network error' })
    }
    setSaving(false)
  }

  const runCloudScan = async () => {
    if (!selectedClientId) return
    setScanning(true)
    setMsg(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/cloud-scan/run`, {
        method: 'POST',
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok) {
        setMsg({ type: 'ok', text: `Agentless scan complete. Findings stored: ${d.findings_count ?? 0}` })
        loadPosture()
      } else {
        setMsg({ type: 'err', text: d.detail || 'Cloud scan failed (check platform AWS credentials and role trust).' })
      }
    } catch {
      setMsg({ type: 'err', text: 'Network error' })
    }
    setScanning(false)
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 text-center text-white/50 text-sm">Select a client to manage cloud IAM and compliance posture.</div>
    )
  }

  const frameworks = Array.isArray(posture?.frameworks) ? posture.frameworks : []

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-white tracking-tight mb-1">Compliance &amp; agentless cloud</h2>
        <p className="text-xs text-white/50 uppercase tracking-widest">
          Cross-account IAM · CNAPP-style posture · mapped to SOC 2 / ISO 27001 / GDPR
        </p>
      </div>

      {msg && (
        <div
          className={`rounded-xl px-4 py-3 text-sm border ${
            msg.type === 'ok' ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-200' : 'border-red-500/40 bg-red-950/40 text-red-200'
          }`}
        >
          {msg.text}
        </div>
      )}

      <section className="rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-6 space-y-4">
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider">Cross-account AWS IAM</h3>
        <p className="text-xs text-white/45 leading-relaxed">
          Enter the customer role ARN to be assumed by this platform (STS). Use an external ID in the role trust policy.
          Platform AWS credentials (instance profile, env, or profile) must be permitted to{' '}
          <code className="text-cyan-300/90">sts:AssumeRole</code> into this role.
        </p>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">IAM role ARN</span>
          <input
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="arn:aws:iam::123456789012:role/WeissmanReadOnly"
            value={arn}
            onChange={(e) => setArn(e.target.value)}
            className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white font-mono placeholder:text-white/25 focus:border-[#22d3ee]/50 focus:outline-none"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">External ID (recommended)</span>
          <input
            type="password"
            autoComplete="new-password"
            value={externalId}
            onChange={(e) => setExternalId(e.target.value)}
            className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white font-mono placeholder:text-white/25 focus:border-[#22d3ee]/50 focus:outline-none"
            placeholder="••••••••"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">GCP project ID (optional)</span>
          <input
            type="text"
            value={gcpProject}
            onChange={(e) => setGcpProject(e.target.value)}
            className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white font-mono focus:border-[#22d3ee]/50 focus:outline-none"
            placeholder="my-gcp-project"
          />
        </label>
        <div className="flex flex-wrap gap-3 pt-2">
          <button
            type="button"
            disabled={saving}
            onClick={saveCloudIntegration}
            className="px-4 py-2 rounded-xl text-sm font-medium border border-[#22d3ee]/40 text-[#22d3ee] hover:bg-[#22d3ee]/10 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save cloud integration'}
          </button>
          <button
            type="button"
            disabled={scanning || !arn.trim()}
            onClick={runCloudScan}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-white/20 bg-white/5 text-white hover:bg-white/10 disabled:opacity-40"
          >
            {scanning ? 'Scanning…' : 'Run agentless AWS scan'}
          </button>
        </div>
      </section>

      <section className="rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-6">
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider mb-4">Compliance posture</h3>
        {postureLoading && <p className="text-sm text-white/40">Loading posture…</p>}
        {!postureLoading && frameworks.length === 0 && (
          <p className="text-sm text-white/45">No framework data (run migrations and ensure compliance_mappings is seeded).</p>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {frameworks.map((f) => (
            <div
              key={f.framework}
              className="rounded-xl border border-white/10 bg-slate-950/80 p-4 flex flex-col gap-1"
            >
              <span className="text-xs uppercase tracking-widest text-white/45">{labelForFramework(f.framework)}</span>
              <span className="text-3xl font-bold text-white tabular-nums">{f.compliance_percent}%</span>
              <span className="text-[11px] text-white/40">Compliant (mapped controls)</span>
              <span className="text-[10px] text-white/30 mt-1">
                {f.violated_controls} / {f.total_mapped_controls} controls with active findings
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
