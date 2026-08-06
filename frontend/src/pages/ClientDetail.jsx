import { useEffect, useState, useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import PremiumPageHeader from '../components/ui/PremiumPageHeader'
import Button from '../components/ui/Button'
import { SkeletonCard } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { confirmDialog } from '../utils/confirmDialog'
import ClientReadinessBanner from '../components/clients/ClientReadinessBanner'

export default function ClientDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [client, setClient] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [launchingScan, setLaunchingScan] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  useEffect(() => {
    loadClient()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  async function loadClient() {
    setLoading(true)
    setError('')
    try {
      const data = await apiFetch(`/api/clients/${id}`)
      setClient(data)
      setLastUpdated(new Date())
    } catch (err) {
      if (err?.status === 404) {
        setError(t('client_detail.not_found'))
      } else if (err?.response) {
        const text = await err.response.text().catch(() => 'Failed to load client')
        setError(`${t('common.error')}: ${text}`)
      } else {
        setError(`${t('common.error')}: ${err.message}`)
      }
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
      const data = await apiFetch(`/api/clients/${client.id}/scan/run-all`, {
        method: 'POST',
      })

      setScanResult({
        success: true,
        message: data.message || t('clients_page.scan_queued', { count: data.jobs_queued ?? 0 }),
        jobs_queued: data.jobs_queued,
        engines: data.engines,
        jobs: data.jobs || [],
      })
    } catch (err) {
      let text
      if (err?.response) {
        const data = await err.response.json().catch(() => null)
        text = data?.detail || data?.code || (await err.response.text().catch(() => null)) || `HTTP ${err.status}`
      } else {
        text = err.message
      }
      setScanResult({ success: false, message: `${t('clients_page.scan_error')}: ${text}` })
    } finally {
      setLaunchingScan(false)
    }
  }

  // Derived findings + workbench must run unconditionally (Rules of Hooks), so
  // they live above the loading/error/not-found early returns and null-guard on
  // `client` (which is null until the fetch resolves).
  const listFindings = useMemo(() => {
    if (!client) return []
    let doms = []
    try {
      const parsed =
        typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
      doms = Array.isArray(parsed) ? parsed : []
    } catch {
      doms = []
    }
    return [
      {
        id: client.id,
        severity: 'info',
        title: client.name,
        type: 'client',
        description: client.contact_email || '',
        resource: doms.join(', '),
      },
    ]
  }, [client])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-client-detail',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

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
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-5 py-4 text-rose-300">
            {error}
          </div>
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className="px-4 py-2 rounded-xl border border-white/12 bg-white/[0.04] text-white/70 hover:text-white font-mono text-sm transition-colors"
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
          <p className="text-white/45">{t('client_detail.not_found')}</p>
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className="mt-6 px-4 py-2 rounded-xl border border-white/12 bg-white/[0.04] text-white/70 hover:text-white font-mono text-sm transition-colors"
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
    'px-3.5 py-2 rounded-xl text-[11px] font-mono border border-white/12 bg-white/[0.03] text-white/65 hover:text-white hover:border-white/25 transition-all whitespace-nowrap'

  return (
    <PageShell
      title={client.name}
      subtitle={t('client_detail.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={loadClient}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
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
          <Button
            variant="unstyled"
            type="button"
            onClick={launchScan}
            disabled={launchingScan}
            className="px-4 py-2 rounded-xl text-[11px] font-mono border border-violet-500/35 bg-violet-500/15 text-violet-100 hover:bg-violet-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition-all whitespace-nowrap"
          >
            {launchingScan ? t('client_detail.launching') : t('client_detail.launch_scan')}
          </Button>
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
              <div className="mt-3 text-xs text-white/55 space-y-1 max-h-48 overflow-y-auto font-mono custom-scroll">
                {scanResult.jobs.slice(0, 12).map((j) => (
                  <div key={j.job_id} className="flex justify-between gap-3">
                    <span className="text-white/40 truncate" title={j.target}>
                      {j.engine} → {j.target}
                    </span>
                    <Link to="/jobs" className="text-cyan-300 hover:text-cyan-200 underline shrink-0">
                      {j.job_id.slice(0, 8)}…
                    </Link>
                  </div>
                ))}
                {scanResult.jobs.length > 12 && (
                  <div className="text-white/35">+{scanResult.jobs.length - 12} more queued</div>
                )}
              </div>
            )}
          </div>
        )}

        <section className="glass-panel rounded-2xl p-6">
          <h3 className="text-sm font-mono uppercase tracking-widest text-white/45 mb-4">
            {t('client_detail.overview')}
          </h3>
          <dl className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <dt className="text-[11px] font-mono text-white/40 uppercase tracking-wide">{t('client_detail.client_name')}</dt>
              <dd className="mt-1 text-white font-semibold">{client.name}</dd>
            </div>
            {client.contact_email && (
              <div>
                <dt className="text-[11px] font-mono text-white/40 uppercase tracking-wide">{t('client_detail.contact_email')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{client.contact_email}</dd>
              </div>
            )}
            {client.created_at && (
              <div>
                <dt className="text-[11px] font-mono text-white/40 uppercase tracking-wide">{t('client_detail.created')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{new Date(client.created_at).toLocaleString()}</dd>
              </div>
            )}
            {client.updated_at && (
              <div>
                <dt className="text-[11px] font-mono text-white/40 uppercase tracking-wide">{t('client_detail.last_updated')}</dt>
                <dd className="mt-1 text-white font-mono text-sm">{new Date(client.updated_at).toLocaleString()}</dd>
              </div>
            )}
          </dl>
        </section>

        <section className="glass-panel rounded-2xl p-6">
          <h3 className="text-sm font-mono uppercase tracking-widest text-white/45 mb-4">
            {t('client_detail.scope')}
          </h3>
          <div className="space-y-6">
            <div>
              <h4 className="text-[11px] font-mono text-white/50 uppercase tracking-wide mb-2">
                {t('client_detail.domains')} ({domains.length})
              </h4>
              {domains.length > 0 ? (
                <ul className="rounded-xl border border-white/8 bg-black/30 p-4 space-y-1.5">
                  {domains.map((domain, idx) => (
                    <li key={idx} className="text-emerald-300/90 font-mono text-sm flex items-center gap-2">
                      <span className="text-emerald-500/60" aria-hidden="true">✓</span>
                      {domain}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-white/35 text-sm font-mono">{t('client_detail.no_domains')}</p>
              )}
            </div>

            {ipRanges.length > 0 && (
              <div>
                <h4 className="text-[11px] font-mono text-white/50 uppercase tracking-wide mb-2">
                  {t('client_detail.ip_ranges')} ({ipRanges.length})
                </h4>
                <ul className="rounded-xl border border-white/8 bg-black/30 p-4 space-y-1.5">
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
            <h3 className="text-sm font-mono uppercase tracking-widest text-white/45 mb-4">
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
          <h3 className="text-sm font-mono uppercase tracking-widest text-white/45 mb-4">
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
                className="group p-4 rounded-xl border border-white/10 bg-black/25 hover:border-white/20 hover:bg-black/35 transition-all text-center"
              >
                <div className="text-white font-semibold text-sm group-hover:text-violet-200 transition-colors">
                  {action.title}
                </div>
                <div className="text-white/40 text-xs mt-1 font-mono">{action.desc}</div>
              </Link>
            ))}
          </div>
        </section>
      </div>
    </PageShell>
  )
}
