/**
 * Board-ready Report view for a client: Executive Summary + Cryptographic Proof of Integrity.
 * Fetches live from /api/clients/:id, /api/clients/:id/report/crypto-proof. No mock data.
 */
import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { useTranslation, Trans } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'
import { apiUrl } from '../lib/apiBase'
import { downloadApiFile } from '../lib/downloadApiFile'
import StandaloneLabShell from './ui/StandaloneLabShell'
import Button from './ui/Button'

export default function ReportView() {
  const { t } = useTranslation()
  const { clientId } = useParams()
  const [client, setClient] = useState(null)
  const [findings, setFindings] = useState([])
  const [cryptoProof, setCryptoProof] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!clientId) return undefined
    let cancelled = false
    setLoading(true)
    setError('')
    setClient(null)
    const ac = new AbortController()
    Promise.all([
      apiFetch('/api/clients', { signal: ac.signal }),
      apiFetch('/api/findings', { signal: ac.signal }),
      apiFetch(`/api/clients/${clientId}/report/crypto-proof`, { signal: ac.signal }),
    ])
      .then(([clients, findingsList, proof]) => {
        if (cancelled) return
        if (clients?.ok === false || clients?.unavailable) {
          throw new Error(clients.detail || t('components.reportView.unavailable'))
        }
        if (findingsList?.ok === false || findingsList?.unavailable) {
          throw new Error(findingsList.detail || t('components.reportView.unavailable'))
        }
        if (proof?.ok === false || proof?.unavailable) {
          throw new Error(proof.detail || t('components.reportView.unavailable'))
        }
        const c = Array.isArray(clients) ? clients.find((x) => String(x?.id) === String(clientId)) : null
        const findingsArr = Array.isArray(findingsList)
          ? findingsList
          : (Array.isArray(findingsList?.findings) ? findingsList.findings : null)
        if (!findingsArr) {
          throw new Error(t('components.reportView.unavailable'))
        }
        setClient(c || null)
        setFindings(findingsArr.filter((f) => String(f.client) === String(clientId) || String(f.client_id) === String(clientId)))
        setCryptoProof(proof?.audit_root_hash ? proof : null)
      })
      .catch((e) => {
        if (cancelled || e?.name === 'AbortError') return
        setError(e?.message || t('components.reportView.unavailable'))
        setClient(null)
        setFindings([])
        setCryptoProof(null)
      })
      .finally(() => {
        if (!cancelled && !ac.signal.aborted) setLoading(false)
      })
    return () => {
      cancelled = true
      ac.abort()
    }
    // Fetch keys on the client only. `t` is closed over solely for fallback error
    // strings; keying the effect on it would re-fire this full clients+findings+
    // crypto-proof reload on every render whenever `t`'s identity churns (e.g. a
    // language-context update), looping re-fetches and clobbering loaded state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId])

  if (loading) {
    return (
      <StandaloneLabShell title={t('components.reportView.loading')}>
        <p className="text-cyan-400" role="status">{t('components.reportView.loading')}</p>
      </StandaloneLabShell>
    )
  }

  const clientName = client?.name || t('components.reportView.client_fallback', { id: clientId })
  const verifiedFindings = findings.filter((f) => !!f?.verified || !!f?.poc_sealed || !!f?.reproduced)
  const verificationBreakdown = verifiedFindings.reduce((acc, f) => {
    // Honest assurance tiers: an independent live re-scan re-observing the finding
    // (`reproduced`) is a strictly stronger signal than a PoC sealed at scan time
    // (`crypto_seal`). Count them separately so the report never inflates the former.
    const key = f?.reproduced
      ? 'reproduced_live'
      : (String(f?.verification_method || (f?.poc_sealed || f?.has_poc ? 'crypto_seal' : 'verified')).trim() || 'verified')
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const breakdownPairs = Object.entries(verificationBreakdown).sort((a, b) => b[1] - a[1])

  return (
    <StandaloneLabShell
      title={t('components.reportView.title', { name: clientName })}
      maxWidth="max-w-4xl"
      actions={!error ? (
        <div className="flex items-center gap-3">
          <Button
            variant="unstyled"
            type="button"
            onClick={() => {
              downloadApiFile(`/api/clients/${clientId}/export/xlsx`, 'Weissman_Board.xlsx').catch((e) => {
                setError(e?.message || t('components.reportView.download_failed'))
              })
            }}
            className="text-sm text-emerald-400 hover:underline"
          >
            {t('components.reportView.download_xlsx')}
          </Button>
          <a
            href={apiUrl(`/api/clients/${clientId}/report/pdf`)}
            download
            className="text-sm text-cyan-400 hover:underline"
          >
            {t('components.reportView.download_pdf')}
          </a>
        </div>
      ) : null}
    >
      {error && (
        <div
          className="mb-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm"
          data-testid="report-unavailable"
          data-live="false"
          role="alert"
        >
          {t('components.reportView.unavailable')}
        </div>
      )}

      {!error && (
      <section className="mb-8">
        <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-2">{t('components.reportView.executive_summary')}</h2>
        <p className="text-[var(--text-tertiary)] text-sm">
          <Trans
            i18nKey="components.reportView.summary_body"
            values={{ name: clientName }}
            components={{ 1: <strong className="text-[var(--text-secondary)]" /> }}
          />
        </p>
        <p className="text-[var(--text-muted)] text-xs mt-2">
          {t('components.reportView.total_findings', { total: findings.length, verified: verifiedFindings.length })}
        </p>
        {breakdownPairs.length > 0 && (
          <p className="text-[var(--text-muted)] text-xs mt-1">
            {t('components.reportView.verified_breakdown')}: {breakdownPairs.map(([k, v]) => `${k}=${v}`).join(' · ')}
          </p>
        )}
      </section>
      )}

      {!error && findings.length > 0 && (
        <section className="mb-8 overflow-x-auto">
          <h2 className="text-lg font-semibold text-[var(--text-secondary)] mb-2">{t('components.reportView.recent_findings')}</h2>
          <table className="w-full border-collapse border border-[var(--border-strong)]">
            <thead>
              <tr className="bg-[var(--bg-3)]/80">
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_id')}</th>
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_title')}</th>
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_severity')}</th>
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_source')}</th>
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_verified')}</th>
                <th className="border border-[var(--border-strong)] px-3 py-2 text-left text-cyan-400 text-sm">{t('components.reportView.col_how')}</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 50).map((f) => (
                <tr key={f.id} className="border-b border-[var(--border-default)]">
                  <td className="px-3 py-2 text-sm">{f.id}</td>
                  <td className="px-3 py-2 text-sm">{f.title || '—'}</td>
                  <td className="px-3 py-2 text-sm">{f.severity || '—'}</td>
                  <td className="px-3 py-2 text-sm">{f.source || '—'}</td>
                  <td className="px-3 py-2 text-sm">{(f.verified || f.poc_sealed || f.reproduced) ? '✓' : '—'}</td>
                  <td className="px-3 py-2 text-xs font-mono text-[var(--text-tertiary)]">{f.reproduced ? 'reproduced (live)' : (f.verification_method || ((f.has_poc || f.poc_sealed) ? 'crypto_seal (PoC)' : '—'))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {!error && (
      <section className="rounded-xl border border-cyan-500/40 bg-[var(--bg-1)]/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-cyan-400 mb-2">{t('components.reportView.crypto_proof')}</h2>
        <p className="text-[var(--text-tertiary)] text-sm mb-4">
          {t('components.reportView.crypto_sealed_body')}
        </p>
        {cryptoProof?.audit_root_hash ? (
          <div className="flex flex-wrap items-start gap-6">
            {cryptoProof.qr_data_url && (
              <img
                src={cryptoProof.qr_data_url}
                alt="QR verification"
                className="w-40 h-40 rounded border border-[var(--border-strong)] bg-white p-1"
              />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-[var(--text-secondary)] text-sm break-all font-mono">
                <strong className="text-cyan-400">{t('components.reportView.audit_root_hash_label')}</strong><br />
                {cryptoProof.audit_root_hash}
              </p>
              {cryptoProof.verification_url && (
                <p className="mt-2 text-sm">
                  <a
                    href={cryptoProof.verification_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline"
                  >
                    {t('components.reportView.verify_link', { url: cryptoProof.verification_url })}
                  </a>
                </p>
              )}
            </div>
          </div>
        ) : (
          <p className="text-[var(--text-muted)] text-sm">
            {t('components.reportView.no_sealed_run')}
          </p>
        )}
      </section>
      )}
    </StandaloneLabShell>
  )
}
