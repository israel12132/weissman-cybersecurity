import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'

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
  const [postureError, setPostureError] = useState(null)

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
      setPostureError(null)
      setPostureLoading(false)
      return
    }
    setPostureLoading(true)
    setPostureError(null)
    const q = `?client_id=${encodeURIComponent(selectedClientId)}`
    apiFetch(`/api/compliance/posture${q}`)
      .then((d) => {
        if (d?.ok === false || d?.unavailable) {
          throw new Error(d.detail || t(`${NS}.unavailable`))
        }
        setPosture(d)
      })
      .catch((e) => {
        setPosture(null)
        setPostureError(e?.message || t(`${NS}.unavailable`))
      })
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
      await apiFetch(`/api/clients/${selectedClientId}/cloud-integration`, {
        method: 'PATCH',
        body: {
          aws_cross_account_role_arn: arn.trim(),
          aws_external_id: externalId.trim(),
          gcp_project_id: gcpProject.trim(),
        },
      })
      setMsg({ type: 'ok', text: t(`${NS}.cloudSaved`) })
      refreshClients()
    } catch (e) {
      if (e?.status) setMsg({ type: 'err', text: e.message || t(`${NS}.saveFailed`) })
      else setMsg({ type: 'err', text: t(`${NS}.networkError`) })
    }
    setSaving(false)
  }

  const runCloudScan = async () => {
    if (!selectedClientId) return
    setScanning(true)
    setMsg(null)
    try {
      const d = await apiFetch(`/api/clients/${selectedClientId}/cloud-scan/run`, {
        method: 'POST',
      })
      setMsg({ type: 'ok', text: t(`${NS}.scanComplete`, { count: d.findings_count ?? 0 }) })
      loadPosture()
    } catch (e) {
      if (e?.status) setMsg({ type: 'err', text: e.message || t(`${NS}.scanFailed`) })
      else setMsg({ type: 'err', text: t(`${NS}.networkError`) })
    }
    setScanning(false)
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 text-center text-[var(--text-muted)] text-sm">{t(`${NS}.selectClient`)}</div>
    )
  }

  const frameworks = Array.isArray(posture?.frameworks) ? posture.frameworks : []

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-8">
      <div>
        <h2 className="text-lg font-semibold text-[var(--text-primary)] tracking-tight mb-1">{t(`${NS}.title`)}</h2>
        <p className="text-xs text-[var(--text-muted)] uppercase tracking-widest">
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

      <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-6 space-y-4">
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider">{t(`${NS}.awsIamTitle`)}</h3>
        <p className="text-xs text-[var(--text-muted)] leading-relaxed">
          {t(`${NS}.awsIamBodyBefore`)}
          <code className="text-cyan-300/90">sts:AssumeRole</code>
          {t(`${NS}.awsIamBodyAfter`)}
        </p>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">{t(`${NS}.roleArnLabel`)}</span>
          <input
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder={t(`${NS}.roleArnPlaceholder`)}
            value={arn}
            onChange={(e) => setArn(e.target.value)}
            className="w-full rounded-lg bg-[var(--table-surface)] border border-[var(--border-strong)] px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder:text-[var(--text-disabled)] focus:border-[#22d3ee]/50 focus:outline-none"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">{t(`${NS}.externalIdLabel`)}</span>
          <input
            type="password"
            autoComplete="new-password"
            value={externalId}
            onChange={(e) => setExternalId(e.target.value)}
            className="w-full rounded-lg bg-[var(--table-surface)] border border-[var(--border-strong)] px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder:text-[var(--text-disabled)] focus:border-[#22d3ee]/50 focus:outline-none"
            placeholder="••••••••"
          />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">{t(`${NS}.gcpProjectLabel`)}</span>
          <input
            type="text"
            value={gcpProject}
            onChange={(e) => setGcpProject(e.target.value)}
            className="w-full rounded-lg bg-[var(--table-surface)] border border-[var(--border-strong)] px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:border-[#22d3ee]/50 focus:outline-none"
            placeholder={t(`${NS}.gcpPlaceholder`)}
          />
        </label>
        <div className="flex flex-wrap gap-3 pt-2">
          <Button variant="unstyled"
            type="button"
            disabled={saving}
            onClick={saveCloudIntegration}
            className="px-4 py-2 rounded-xl text-sm font-medium border border-[#22d3ee]/40 text-[#22d3ee] hover:bg-[#22d3ee]/10 disabled:opacity-50"
          >
            {saving ? t(`${NS}.saving`) : t(`${NS}.saveCloudIntegration`)}
          </Button>
          <Button variant="unstyled"
            type="button"
            disabled={scanning || !arn.trim()}
            onClick={runCloudScan}
            className="px-4 py-2 rounded-xl text-sm font-semibold border border-[var(--border-strong)] bg-[var(--bg-2)] text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-40"
          >
            {scanning ? t(`${NS}.scanning`) : t(`${NS}.runAgentlessScan`)}
          </Button>
        </div>
      </section>

      <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-6">
        <h3 className="text-sm font-semibold text-[#22d3ee] uppercase tracking-wider mb-4">{t(`${NS}.postureTitle`)}</h3>
        {postureLoading && <p className="text-sm text-[var(--text-muted)]">{t(`${NS}.loadingPosture`)}</p>}
        {!postureLoading && postureError && (
          <p className="text-sm text-red-300" data-testid="compliance-posture-unavailable" role="alert">
            {t(`${NS}.unavailable`)}
          </p>
        )}
        {!postureLoading && !postureError && frameworks.length === 0 && (
          <p className="text-sm text-[var(--text-muted)]">{t(`${NS}.noFrameworkData`)}</p>
        )}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {frameworks.map((f) => (
            <div
              key={f.framework}
              className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-0)]/80 p-4 flex flex-col gap-1"
            >
              <span className="text-xs uppercase tracking-widest text-[var(--text-muted)]">{labelForFramework(f.framework)}</span>
              <span className="text-3xl font-bold text-[var(--text-primary)] tabular-nums">{f.compliance_percent}%</span>
              <span className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.compliantMapped`)}</span>
              <span className="text-[10px] text-[var(--text-muted)] mt-1">
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
