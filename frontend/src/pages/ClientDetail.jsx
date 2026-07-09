import { useEffect, useState, useMemo, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Download } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useToast } from '../components/ui/Toaster'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import PremiumPageHeader from '../components/ui/PremiumPageHeader'
import { SkeletonCard } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import { confirmDialog } from '../utils/confirmDialog'
import ClientReadinessBanner from '../components/clients/ClientReadinessBanner'

export default function ClientDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const { toast } = useToast()
  const [client, setClient] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [launchingScan, setLaunchingScan] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [exportingServer, setExportingServer] = useState(false)

  // Authoritative server-side per-client findings CSV — every finding for this
  // client, not just the rows loaded/filtered in the browser.
  // Wired to GET /api/clients/:id/export/csv.
  const exportServerCsv = useCallback(async () => {
    setExportingServer(true)
    try {
      const r = await apiFetch(`/api/clients/${id}/export/csv`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const disposition = r.headers.get('content-disposition') || ''
      const match = disposition.match(/filename="?([^";\s]+)"?/)
      const filename = match?.[1] ?? `weissman-client${id}-findings-${new Date().toISOString().slice(0, 10)}.csv`
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      toast.success(t('client_detail.export_server_ok'))
    } catch (e) {
      toast.error(e.message || t('client_detail.export_server_failed'))
    } finally {
      setExportingServer(false)
    }
  }, [id, t, toast])

  // Findings workbench — declared before any early return so hook order is
  // stable across renders (null-safe while the client is still loading).
  const listFindings = useMemo(() => {
    if (!client) return []
    let domainStr = ''
    try {
      const parsed = typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
      domainStr = Array.isArray(parsed) ? parsed.join(', ') : ''
    } catch {
      domainStr = ''
    }
    return [{
      id: client.id,
      severity: 'info',
      title: client.name,
      type: 'client',
      description: client.contact_email || '',
      resource: domainStr,
    }]
  }, [client])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-client-detail',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  useEffect(() => {
    loadClient()
  }, [id])

  async function loadClient() {
    setLoading(true)
    setError('')
    try {
      const response = await apiFetch(`/api/clients/${id}`)
      if (!response.ok) {
        if (response.status === 404) {
          setError(t('client_detail.not_found'))
        } else {
          const text = await response.text().catch(() => 'Failed to load client')
          setError(`${t('common.error')}: ${text}`)
        }
        setLoading(false)
        return
      }
      const data = await response.json()
      setClient(data)
      setLastUpdated(new Date())
    } catch (err) {
      setError(`${t('common.error')}: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  async function launchScan() {
    const ok = await confirmDialog({
      title: t('clients_page.scan_title'),
      message: t('clients_page.scan_confirm', { name: client.name }),
      confirmLabel: t('clients_page.scan_action'),
      cancelLabel: t('common.cancel'),
      variant: 'primary',
    })
    if (!ok) return

    setLaunchingScan(true)
    setScanResult(null)

    try {
      const response = await apiFetch(`/api/clients/${client.id}/scan/run-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })

      if (!response.ok) {
        const data = await response.json().catch(() => null)
        const text = data?.detail || data?.code || (await response.text().catch(() => null)) || `HTTP ${response.status}`
        setScanResult({ success: false, message: `${t('clients_page.scan_error')}: ${text}` })
        return
      }

      const data = await response.json()
      setScanResult({
        success: true,
        message: data.message || t('clients_page.scan_queued', { count: data.jobs_queued ?? 0 }),
        jobs_queued: data.jobs_queued,
        engines: data.engines,
        jobs: data.jobs || [],
      })
    } catch (err) {
      setScanResult({ success: false, message: `${t('clients_page.scan_error')}: ${err.message}` })
    } finally {
      setLaunchingScan(false)
    }
  }

  if (loading) {
    return (
      <PageShell title={t('client_detail.title')} subtitle={t('client_detail.loading')}>
        <div className="max-w-5xl mx-auto space-y-5">
          <SkeletonCard lines={2} className="h-24" />
          <SkeletonCard lines={5} />
          <SkeletonCard lines={6} />
        </div>
      </PageShell>
    )
  }

  if (error) {
    return (
      <PageShell title={t('client_detail.title')} subtitle={t('common.error')}>
        <div className="max-w-2xl mx-auto space-y-5">
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-5 py-4 text-rose-300">
            {error}
          </div>
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className="px-4 py-2 rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] font-mono text-sm transition-colors"
          >
            {t('client_detail.back')}
          </button>
        </div>
      </PageShell>
    )
  }

  if (!client) {
    return (
      <PageShell title={t('client_detail.title')} subtitle={t('client_detail.not_found')}>
        <div className="max-w-2xl mx-auto text-center py-12">
          <p className="text-[var(--text-muted)]">{t('client_detail.not_found')}</p>
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className="mt-6 px-4 py-2 rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] font-mono text-sm transition-colors"
          >
            {t('client_detail.back')}
          </button>
        </div>
      </PageShell>
    )
  }

  const domains = (() => {
    try {
      const parsed = typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  const ipRanges = (() => {
    try {
      const parsed = typeof client.ip_ranges === 'string' ? JSON.parse(client.ip_ranges) : client.ip_ranges
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  const techStack = (() => {
    try {
      const parsed = typeof client.tech_stack === 'string' ? JSON.parse(client.tech_stack) : client.tech_stack
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  const navBtnClass =
    'px-3.5 py-2 rounded-xl text-[11px] font-mono border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all whitespace-nowrap'

  return (
    <PageShell
      title={client.name}
      subtitle={t('client_detail.subtitle')}
      actions={(
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={exportServerCsv}
            disabled={exportingServer}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-200 text-xs font-mono hover:bg-violet-500/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title={t('client_detail.export_server_hint')}
          >
            <Download className={`w-4 h-4 ${exportingServer ? 'animate-pulse' : ''}`} />
            {exportingServer ? t('client_detail.export_server_running') : t('client_detail.export_server')}
          </button>
          <ShellScanActions
            onRefresh={loadClient}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredFindings.length}
          />
        </div>
      )}
    >
      <div className="max-w-5xl mx-auto space-y-5">
        <ClientReadinessBanner clientId={client.id} />
        <PremiumPageHeader
          title={client.name}
          subtitle={t('client_detail.subtitle')}
          badge={t('findings.live_badge')}
          badgeColor="#8b5cf6"
          lastUpdated={lastUpdated}
          onRefresh={loadClient}
          refreshLabel={t('common.refresh')}
        >
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className={navBtnClass}
          >
            {t('client_detail.back')}
          </button>
          <Link to={`/findings?client_id=${client.id}`} className={navBtnClass}>
            {t('client_detail.view_findings')}
          </Link>
          <button
            type="button"
            onClick={launchScan}
            disabled={launchingScan}
            className="px-4 py-2 rounded-xl text-[11px] font-mono border border-violet-500/35 bg-violet-500/15 text-violet-100 hover:bg-violet-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition-all whitespace-nowrap"
          >
            {launchingScan ? t('client_detail.launching') : t('client_detail.launch_scan')}
          </button>
        </PremiumPageHeader>

        <div className="flex flex-wrap gap-2">
          <Link to={`/clients/${client.id}/integrations`} className={navBtnClass}>
            {t('client_detail.integrations')}
          </Link>
          <Link to={`/clients/${client.id}/engagements`} className={navBtnClass}>
            {t('client_detail.engagements')}
          </Link>
          <Link to={`/clients/${client.id}/evidence`} className={navBtnClass}>
            {t('client_detail.evidence_vault')}
          </Link>
          <Link to={`/clients/${client.id}/discovery/saas-idp`} className={navBtnClass}>
            {t('client_detail.saas_discovery')}
          </Link>
        </div>

        {scanResult && (
          <div
            className={`rounded-xl border px-4 py-3 ${
              scanResult.success
                ? 'bg-emerald-950/25 border-emerald-500/30 text-emerald-200'
                : 'bg-rose-950/25 border-rose-500/30 text-rose-300'
            }`}
          >
            <p className="font-medium text-sm">{scanResult.message}</p>
            {Array.isArray(scanResult.jobs) && scanResult.jobs.length > 0 && (
              <div className="mt-3 text-xs text-[var(--text-tertiary)] space-y-1 max-h-48 overflow-y-auto font-mono custom-scroll">
                {scanResult.jobs.slice(0, 12).map((j) => (
                  <div key={j.job_id} className="flex justify-between gap-3">
                    <span className="text-[var(--text-muted)] truncate" title={j.target}>
                      {j.engine} → {j.target}
                    </span>
                    <Link to="/jobs" className="text-cyan-300 hover:text-cyan-200 underline shrink-0">
                      {j.job_id.slice(0, 8)}…
                    </Link>
                  </div>
                ))}
                {scanResult.jobs.length > 12 && (
                  <div className="text-[var(--text-muted)]">+{scanResult.jobs.length - 12} more queued</div>
                )}
              </div>
            )}
          </div>
        )}

        <section className="glass-panel rounded-2xl p-6">
          <h3 className="text-sm font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">
            {t('client_detail.overview')}
          </h3>
          <dl className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <dt className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('client_detail.client_name')}</dt>
              <dd className="mt-1 text-white font-semibold">{client.name}</dd>
            </div>
            {client.contact_email && (
              <div>
                <dt className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('client_detail.contact_email')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{client.contact_email}</dd>
              </div>
            )}
            {client.created_at && (
              <div>
                <dt className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('client_detail.created')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{new Date(client.created_at).toLocaleString()}</dd>
              </div>
            )}
            {client.updated_at && (
              <div>
                <dt className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('client_detail.last_updated')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{new Date(client.updated_at).toLocaleString()}</dd>
              </div>
            )}
          </dl>
        </section>

        <section className="glass-panel rounded-2xl p-6">
          <h3 className="text-sm font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">
            {t('client_detail.scope')}
          </h3>
          <div className="space-y-6">
            <div>
              <h4 className="text-[11px] font-mono text-[var(--text-tertiary)] uppercase tracking-wide mb-2">
                {t('client_detail.domains')} ({domains.length})
              </h4>
              {domains.length > 0 ? (
                <ul className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-4 space-y-1.5">
                  {domains.map((domain, idx) => (
                    <li key={idx} className="text-emerald-300/90 font-mono text-sm flex items-center gap-2">
                      <span className="text-emerald-500/60" aria-hidden="true">✓</span>
                      {domain}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[var(--text-muted)] text-sm font-mono">{t('client_detail.no_domains')}</p>
              )}
            </div>

            {ipRanges.length > 0 && (
              <div>
                <h4 className="text-[11px] font-mono text-[var(--text-tertiary)] uppercase tracking-wide mb-2">
                  {t('client_detail.ip_ranges')} ({ipRanges.length})
                </h4>
                <ul className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-4 space-y-1.5">
                  {ipRanges.map((range, idx) => (
                    <li key={idx} className="text-cyan-300/90 font-mono text-sm flex items-center gap-2">
                      <span className="text-cyan-500/60" aria-hidden="true">✓</span>
                      {range}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </section>

        {techStack.length > 0 && (
          <section className="glass-panel rounded-2xl p-6">
            <h3 className="text-sm font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">
              {t('client_detail.tech_stack')}
            </h3>
            <div className="flex flex-wrap gap-2">
              {techStack.map((tech, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded-full text-sm font-mono border border-violet-500/30 bg-violet-500/10 text-violet-200"
                >
                  {tech}
                </span>
              ))}
            </div>
          </section>
        )}

        <section className="glass-panel rounded-2xl p-6">
          <h3 className="text-sm font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">
            {t('client_detail.quick_actions')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                to: `/findings?client_id=${client.id}`,
                title: t('client_detail.view_findings'),
                desc: t('client_detail.view_findings_desc'),
                accent: 'violet',
              },
              {
                to: `/report/${client.id}`,
                title: t('client_detail.generate_report'),
                desc: t('client_detail.generate_report_desc'),
                accent: 'cyan',
              },
              {
                to: `/attack-surface-graph/${client.id}`,
                title: t('client_detail.attack_surface'),
                desc: t('client_detail.attack_surface_desc'),
                accent: 'amber',
              },
            ].map((action) => (
              <Link
                key={action.to}
                to={action.to}
                className="group p-4 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] hover:border-[var(--border-strong)] hover:bg-[var(--table-surface)] transition-all text-center"
              >
                <div className="text-white font-semibold text-sm group-hover:text-violet-200 transition-colors">
                  {action.title}
                </div>
                <div className="text-[var(--text-muted)] text-xs mt-1 font-mono">{action.desc}</div>
              </Link>
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  )
}
