import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

function prettyVendor(v) {
  const m = {
    okta: 'Okta',
    azure_ad: 'Azure AD / Entra ID',
    google: 'Google Workspace',
    ping: 'Ping Identity',
    onelogin: 'OneLogin',
    jumpcloud: 'JumpCloud',
    duo: 'Duo',
    adfs: 'ADFS (on-prem)',
  }
  return m[String(v || '').toLowerCase()] || String(v || 'Unknown')
}

function pct(n) {
  const v = Number(n)
  if (!Number.isFinite(v)) return '0%'
  return `${Math.round(v * 100)}%`
}

export default function ClientSaasIdpDiscovery() {
  const { id } = useParams()
  const clientId = useMemo(() => String(id || '').trim(), [id])

  const [clientName, setClientName] = useState('')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

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
        setError(data?.detail || data?.error || `Discovery failed (HTTP ${res.status})`)
        return
      }
      setClientName(data?.client_name || '')
      setReport(data?.report || null)
    } catch (e) {
      setError(e?.message || 'Network error')
    } finally {
      setLoading(false)
      setRunning(false)
    }
  }

  async function copy(text) {
    const t = String(text || '').trim()
    if (!t) return
    try {
      await navigator.clipboard.writeText(t)
      alert('Copied to clipboard.')
    } catch {
      alert(t)
    }
  }

  const domains = Array.isArray(report?.domains_considered) ? report.domains_considered : []
  const idps = Array.isArray(report?.idp_candidates) ? report.idp_candidates : []
  const saas = Array.isArray(report?.saas_signals) ? report.saas_signals : []

  if (loading) {
    return (
      <PageShell title="SaaS / IdP Discovery" subtitle="Loading...">
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">Running discovery...</p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell
      title={`SaaS / IdP Discovery${clientName ? ` — ${clientName}` : ''}`}
      subtitle="Best-effort hints from DNS + OIDC discovery + landing probes (audit logged)"
    >
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <Link to={`/clients/${clientId}`} className="text-sm text-slate-400 hover:text-slate-200">
            ← Back to Client
          </Link>
          <button
            type="button"
            onClick={runDiscovery}
            disabled={running}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
          >
            {running ? 'Running…' : 'Re-run Discovery'}
          </button>
        </div>

        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">Domains Considered</h2>
          <div className="mt-2 text-sm text-slate-300">
            {domains.length === 0 ? (
              <span className="text-slate-400">No domains configured for this client yet.</span>
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
            Configure domains in the client record to improve discovery coverage.
          </div>
        </div>

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">IdP Candidates</h2>
          {idps.length === 0 ? (
            <div className="mt-2 text-sm text-slate-400">No strong IdP signals detected yet.</div>
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
                          <div className="text-white font-semibold">{prettyVendor(c.vendor)}</div>
                          <div className="text-xs text-slate-400 mt-1">
                            Confidence: <span className="font-mono text-slate-200">{pct(c.confidence)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {issuer && (
                            <button
                              type="button"
                              onClick={() => copy(issuer)}
                              className="px-3 py-1 text-xs bg-slate-700 text-white rounded hover:bg-slate-600"
                            >
                              Copy Issuer URL
                            </button>
                          )}
                          {finalHost && (
                            <button
                              type="button"
                              onClick={() => copy(finalHost)}
                              className="px-3 py-1 text-xs bg-slate-700 text-white rounded hover:bg-slate-600"
                            >
                              Copy Host
                            </button>
                          )}
                          <Link
                            to="/sso-config"
                            className="px-3 py-1 text-xs bg-purple-700 text-white rounded hover:bg-purple-600"
                          >
                            Go to SSO Config
                          </Link>
                        </div>
                      </div>

                      {issuer && (
                        <div className="mt-3 text-[12px] text-slate-300 font-mono break-all">
                          issuer: {issuer}
                        </div>
                      )}
                      {finalHost && (
                        <div className="mt-1 text-[12px] text-slate-400 font-mono break-all">
                          host: {finalHost}
                        </div>
                      )}
                      <div className="mt-3 text-xs text-slate-500">
                        This is a hint engine — verify the IdP settings before enabling production SSO.
                      </div>
                    </div>
                  )
                })}
            </div>
          )}
        </div>

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <h2 className="text-lg font-semibold text-white">SaaS Signals</h2>
          {saas.length === 0 ? (
            <div className="mt-2 text-sm text-slate-400">No SaaS signals from SPF includes yet.</div>
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

