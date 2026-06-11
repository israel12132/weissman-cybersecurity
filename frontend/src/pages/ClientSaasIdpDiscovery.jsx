import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

function pct(n) {
  const v = Number(n)
  if (!Number.isFinite(v)) return '0%'
  return `${Math.round(v * 100)}%`
}

export default function ClientSaasIdpDiscovery() {
  const { t } = useTranslation()
  const { id } = useParams()
  const clientId = useMemo(() => String(id || '').trim(), [id])

  const [clientName, setClientName] = useState('')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  function vendorLabel(vendor) {
    const key = String(vendor || '').toLowerCase()
    return t(`pages.clientSaasIdpDiscovery.vendors.${key}`, {
      defaultValue: String(vendor || t('pages.clientSaasIdpDiscovery.vendor_unknown')),
    })
  }

  useEffect(() => {
    if (!clientId) return
    runDiscovery()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId])

  async function runDiscovery() {
    setRunning(true)
    setError('')
    try {
      const res = await apiFetch(`/api/clients/${clientId}/discovery/saas-idp`)
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data?.detail || data?.error || t('pages.clientSaasIdpDiscovery.discovery_failed', { status: res.status }))
        return
      }
      setClientName(data?.client_name || '')
      setReport(data?.report || null)
    } catch (e) {
      setError(e?.message || t('pages.clientSaasIdpDiscovery.network_error'))
    } finally {
      setLoading(false)
      setRunning(false)
    }
  }

  async function copy(value) {
    const text = String(value || '').trim()
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      alert(t('pages.clientSaasIdpDiscovery.copied'))
    } catch {
      alert(text)
    }
  }

  const domains = Array.isArray(report?.domains_considered) ? report.domains_considered : []
  const idps = Array.isArray(report?.idp_candidates) ? report.idp_candidates : []
  const saas = Array.isArray(report?.saas_signals) ? report.saas_signals : []

  if (loading) {
    return (
      <PageShell title={t('pages.clientSaasIdpDiscovery.title')} subtitle={t('pages.clientEngagements.loading_subtitle')}>
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">{t('pages.clientSaasIdpDiscovery.loading')}</p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell
      title={clientName ? `${t('pages.clientSaasIdpDiscovery.title')} — ${clientName}` : t('pages.clientSaasIdpDiscovery.title')}
      subtitle={t('pages.clientSaasIdpDiscovery.subtitle')}
    >
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <Link to={`/clients/${clientId}`} className="text-sm text-slate-400 hover:text-slate-200">
            {t('pages.clientSaasIdpDiscovery.back_to_client')}
          </Link>
          <button
            type="button"
            onClick={runDiscovery}
            disabled={running}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
          >
            {running ? t('pages.clientSaasIdpDiscovery.running') : t('pages.clientSaasIdpDiscovery.rerun')}
          </button>
        </div>

        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">{t('pages.clientSaasIdpDiscovery.domains_heading')}</h2>
          <div className="mt-2 text-sm text-slate-300">
            {domains.length === 0 ? (
              <span className="text-slate-400">{t('pages.clientSaasIdpDiscovery.empty_domains')}</span>
            ) : (
              <div className="flex flex-wrap gap-2">
                {domains.map((d) => (
                  <span key={d} className="px-2 py-1 rounded bg-slate-900/60 border border-slate-700 font-mono text-[12px]">
                    {d}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="mt-3 text-xs text-slate-500">
            {t('pages.clientSaasIdpDiscovery.domains_hint')}
          </div>
        </div>

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">{t('pages.clientSaasIdpDiscovery.idp_heading')}</h2>
          {idps.length === 0 ? (
            <div className="mt-2 text-sm text-slate-400">{t('pages.clientSaasIdpDiscovery.empty_idp')}</div>
          ) : (
            <div className="mt-4 space-y-3">
              {idps
                .slice()
                .sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0))
                .map((c) => {
                  const top = c?.top_signal || {}
                  const issuer = top?.issuer || ''
                  const finalHost = top?.final_host || top?.vendor_host || ''
                  return (
                    <div key={c.vendor} className="p-4 bg-slate-900/40 border border-slate-700 rounded-lg">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="text-white font-semibold">{vendorLabel(c.vendor)}</div>
                          <div className="text-xs text-slate-400 mt-1">
                            {t('pages.clientSaasIdpDiscovery.confidence', { pct: pct(c.confidence) })}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {issuer && (
                            <button
                              type="button"
                              onClick={() => copy(issuer)}
                              className="px-3 py-1 text-xs bg-slate-700 text-white rounded hover:bg-slate-600"
                            >
                              {t('pages.clientSaasIdpDiscovery.copy_issuer')}
                            </button>
                          )}
                          {finalHost && (
                            <button
                              type="button"
                              onClick={() => copy(finalHost)}
                              className="px-3 py-1 text-xs bg-slate-700 text-white rounded hover:bg-slate-600"
                            >
                              {t('pages.clientSaasIdpDiscovery.copy_host')}
                            </button>
                          )}
                          <Link
                            to="/sso-config"
                            className="px-3 py-1 text-xs bg-purple-700 text-white rounded hover:bg-purple-600"
                          >
                            {t('pages.clientSaasIdpDiscovery.go_sso_config')}
                          </Link>
                        </div>
                      </div>

                      {issuer && (
                        <div className="mt-3 text-[12px] text-slate-300 font-mono break-all">
                          {t('pages.clientSaasIdpDiscovery.issuer_label', { value: issuer })}
                        </div>
                      )}
                      {finalHost && (
                        <div className="mt-1 text-[12px] text-slate-400 font-mono break-all">
                          {t('pages.clientSaasIdpDiscovery.host_label', { value: finalHost })}
                        </div>
                      )}
                      <div className="mt-3 text-xs text-slate-500">
                        {t('pages.clientSaasIdpDiscovery.idp_hint')}
                      </div>
                    </div>
                  )
                })}
            </div>
          )}
        </div>

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">{t('pages.clientSaasIdpDiscovery.saas_heading')}</h2>
          {saas.length === 0 ? (
            <div className="mt-2 text-sm text-slate-400">{t('pages.clientSaasIdpDiscovery.empty_saas')}</div>
          ) : (
            <div className="mt-4 space-y-3">
              {saas.map((s) => (
                <div key={s.name} className="p-4 bg-slate-900/40 border border-slate-700 rounded-lg">
                  <div className="text-white font-semibold">{s.name}</div>
                  <div className="mt-2 text-xs text-slate-300 font-mono space-y-1">
                    {(Array.isArray(s.evidence) ? s.evidence : []).slice(0, 10).map((e) => (
                      <div key={e} className="break-all">{e}</div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}
