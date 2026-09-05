/**
 * Board-ready Report view for a client: Executive Summary + Cryptographic Proof of Integrity.
 * Fetches live from /api/clients/:id, /api/clients/:id/report/crypto-proof. No mock data.
 */
import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { useTranslation, Trans } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'
import StandaloneLabShell from './ui/StandaloneLabShell'
import ClientReportDownloadBar from './ClientReportDownloadBar'

export default function ReportView() {
  const { t } = useTranslation()
  const { clientId } = useParams()
  const [client, setClient] = useState(null)
  const [findings, setFindings] = useState([])
  const [cryptoProof, setCryptoProof] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!clientId) return
    Promise.all([
      apiFetch(`/api/clients/${clientId}`).catch(() => null),
      apiFetch(`/api/clients/${clientId}/findings`).catch(() => ({ findings: [] })),
      apiFetch(`/api/clients/${clientId}/report/crypto-proof`).catch(() => null),
    ])
      .then(([c, findingsPayload, proof]) => {
        setClient(c && typeof c === 'object' ? c : null)
        const list = Array.isArray(findingsPayload?.findings)
          ? findingsPayload.findings
          : Array.isArray(findingsPayload)
            ? findingsPayload
            : []
        setFindings(list)
        setCryptoProof(proof?.audit_root_hash ? proof : null)
      })
      .catch((e) => setError(e?.message || t('components.reportView.load_failed')))
      .finally(() => setLoading(false))
  }, [clientId, t])

  if (loading) {
    return (
      <StandaloneLabShell title={t('components.reportView.loading')}>
        <p className="text-cyan-400" role="status">{t('components.reportView.loading')}</p>
      </StandaloneLabShell>
    )
  }

  const clientName = client?.name || t('components.reportView.client_fallback', { id: clientId })
  const verifiedFindings = findings.filter((f) => !!f?.verified || !!f?.poc_sealed)
  const verificationBreakdown = verifiedFindings.reduce((acc, f) => {
    const raw = String(f?.verification_method || (f?.poc_sealed ? 'crypto_seal' : 'verified') || '').trim()
    const key = raw || 'verified'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const breakdownPairs = Object.entries(verificationBreakdown).sort((a, b) => b[1] - a[1])

  return (
    <StandaloneLabShell
      title={t('components.reportView.title', { name: clientName })}
      maxWidth="max-w-4xl"
      actions={null}
    >
      <ClientReportDownloadBar clientId={clientId} className="mb-6" />
      {error && (
        <div className="mb-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}

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

      {findings.length > 0 && (
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
                  <td className="px-3 py-2 text-sm">{(f.verified || f.poc_sealed) ? '✓' : '—'}</td>
                  <td className="px-3 py-2 text-xs font-mono text-[var(--text-tertiary)]">{f.verification_method || (f.poc_sealed ? 'crypto_seal' : '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

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
    </StandaloneLabShell>
  )
}
