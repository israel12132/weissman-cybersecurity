import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../lib/apiBase'

const NS = 'components.cockpitTabs.complianceDashboard'

export default function ComplianceDashboardTab() {
  const { t } = useTranslation()
  const { selectedClient, selectedClientId, refreshClients } = useClient()
  const [arn, setArn] = useState('')
  const [externalId, setExternalId] = useState('')
  const [gcpProject, setGcpProject] = useState('')
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [msg, setMsg] = useState(null)
  const [posture, setPosture] = useState(null)
  const [postureLoading, setPostureLoading] = useState(true)

  const labelForFramework = (fw) => t(`${NS}.frameworks.${fw}`, fw)

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
        setMsg({ type: 'ok', text: t(`${NS}.cloudSaved`) })
        refreshClients()
      } else {
        setMsg({ type: 'err', text: d.detail || t(`${NS}.saveFailed`) })
      }
    } catch {
      setMsg({ type: 'err', text: t(`${NS}.networkError`) })
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
        setMsg({ type: 'ok', text: t(`${NS}.scanComplete`, { count: d.findings_count ?? 0 }) })
        loadPosture()
      } else {
        setMsg({ type: 'err', text: d.detail || t(`${NS}.scanFailed`) })
      }
    } catch {
      setMsg({ type: 'err', text: t(`${NS}.networkError`) })
    }
    setScanning(false)
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 text-center text-white/50 text-sm">{t(`${NS}.selectClient`)}</div>
    )
  }

  const frameworks = Array.isArray(posture?.frameworks) ? posture.frameworks : []

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-white tracking-tight mb-1">{t(`${NS}.title`)}</h2>
        <p className="text-xs text-white/50 uppercase tracking-widest">
          {t(`${NS}.subtitle`)}
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
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider">{t(`${NS}.awsIamTitle`)}</h3>
        <p className="text-xs text-white/45 leading-relaxed">
          {t(`${NS}.awsIamBodyBefore`)}
          <code className="text-cyan-300/90">sts:AssumeRole</code>
          {t(`${NS}.awsIamBodyAfter`)}
        </p>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">{t(`${NS}.roleArnLabel`)}</span>
          <input
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder={t(`${NS}.roleArnPlaceholder`)}
            value={arn}
            onChange={(e) => setArn(e.target.value)}
            className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white font-mono placeholder:text-white/25 focus:border-[#22d3ee]/50 focus:outline-none"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">{t(`${NS}.externalIdLabel`)}</span>
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
          <span className="text-xs uppercase tracking-widest text-white/50 block mb-1.5">{t(`${NS}.gcpProjectLabel`)}</span>
          <input
            type="text"
            value={gcpProject}
            onChange={(e) => setGcpProject(e.target.value)}
            className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white font-mono focus:border-[#22d3ee]/50 focus:outline-none"
            placeholder={t(`${NS}.gcpPlaceholder`)}
          />
        </label>
        <div className="flex flex-wrap gap-3 pt-2">
          <button
            type="button"
            disabled={saving}
            onClick={saveCloudIntegration}
            className="px-4 py-2 rounded-xl text-sm font-medium border border-[#22d3ee]/40 text-[#22d3ee] hover:bg-[#22d3ee]/10 disabled:opacity-50"
          >
            {saving ? t(`${NS}.saving`) : t(`${NS}.saveCloudIntegration`)}
          </button>
          <button
            type="button"
            disabled={scanning || !arn.trim()}
            onClick={runCloudScan}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-white/20 bg-white/5 text-white hover:bg-white/10 disabled:opacity-40"
          >
            {scanning ? t(`${NS}.scanning`) : t(`${NS}.runAgentlessScan`)}
          </button>
        </div>
      </section>

      <section className="rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-6">
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider mb-4">{t(`${NS}.postureTitle`)}</h3>
        {postureLoading && <p className="text-sm text-white/40">{t(`${NS}.loadingPosture`)}</p>}
        {!postureLoading && frameworks.length === 0 && (
          <p className="text-sm text-white/45">{t(`${NS}.noFrameworkData`)}</p>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {frameworks.map((f) => (
            <div
              key={f.framework}
              className="rounded-xl border border-white/10 bg-[var(--bg-0)]/80 p-4 flex flex-col gap-1"
            >
              <span className="text-xs uppercase tracking-widest text-white/45">{labelForFramework(f.framework)}</span>
              <span className="text-3xl font-bold text-white tabular-nums">{f.compliance_percent}%</span>
              <span className="text-[11px] text-white/40">{t(`${NS}.compliantMapped`)}</span>
              <span className="text-[10px] text-white/30 mt-1">
                {t(`${NS}.controlsWithFindings`, {
                  violated: f.violated_controls,
                  total: f.total_mapped_controls,
                })}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
