/**
 * Board-ready Report view for a client: Executive Summary + Cryptographic Proof of Integrity.
 * Fetches live from /api/clients/:id, /api/clients/:id/report/crypto-proof. No mock data.
 */
import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import { apiFetch, apiUrl } from '../lib/apiBase'

export default function ReportView() {
  const { clientId } = useParams()
  const [client, setClient] = useState(null)
  const [findings, setFindings] = useState([])
  const [cryptoProof, setCryptoProof] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!clientId) return
    Promise.all([
      apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])),
      apiFetch('/api/findings').then((r) => (r.ok ? r.json() : [])),
      apiFetch(`/api/clients/${clientId}/report/crypto-proof`).then((r) => (r.ok ? r.json() : null)),
    ])
      .then(([clients, findingsList, proof]) => {
        const c = Array.isArray(clients) ? clients.find((x) => String(x?.id) === String(clientId)) : null
        setClient(c || null)
        setFindings(Array.isArray(findingsList) ? findingsList.filter((f) => String(f.client) === String(clientId)) : [])
        setCryptoProof(proof?.audit_root_hash ? proof : null)
      })
      .catch((e) => setError(e?.message || 'Load failed'))
      .finally(() => setLoading(false))
  }, [clientId])

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <p className="text-cyan-400">Loading report…</p>
      </div>
    )
  }

  const clientName = client?.name || `Client ${clientId}`

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6 max-w-4xl mx-auto">
      <header className="flex items-center justify-between border-b border-slate-700 pb-4 mb-6">
        <h1 className="text-xl font-bold text-cyan-400">Report — {clientName}</h1>
        <div className="flex gap-4">
          <a
            href={apiUrl(`/api/clients/${clientId}/report/pdf`)}
            download
            className="text-sm text-cyan-400 hover:underline"
          >
            Download PDF (HTML)
          </a>
          <Link to="/" className="text-sm text-slate-400 hover:text-cyan-400">← War Room</Link>
        </div>
      </header>

      {error && (
        <div className="mb-4 p-3 rounded bg-rose-500/20 border border-rose-400/50 text-rose-300 text-sm">
          {error}
        </div>
      )}

      <section className="mb-8">
        <h2 className="text-lg font-semibold text-slate-200 mb-2">Executive Summary</h2>
        <p className="text-slate-400 text-sm">
          Security assessment for <strong className="text-slate-300">{clientName}</strong>. Findings are live from the database.
        </p>
        <p className="text-slate-500 text-xs mt-2">
          Total findings: {findings.length}
        </p>
      </section>

      {findings.length > 0 && (
        <section className="mb-8 overflow-x-auto">
          <h2 className="text-lg font-semibold text-slate-200 mb-2">Recent Findings</h2>
          <table className="w-full border-collapse border border-slate-600">
            <thead>
              <tr className="bg-slate-800/80">
                <th className="border border-slate-600 px-3 py-2 text-left text-cyan-400 text-sm">ID</th>
                <th className="border border-slate-600 px-3 py-2 text-left text-cyan-400 text-sm">Title</th>
                <th className="border border-slate-600 px-3 py-2 text-left text-cyan-400 text-sm">Severity</th>
                <th className="border border-slate-600 px-3 py-2 text-left text-cyan-400 text-sm">Source</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 50).map((f) => (
                <tr key={f.id} className="border-b border-slate-700">
                  <td className="px-3 py-2 text-sm">{f.id}</td>
                  <td className="px-3 py-2 text-sm">{f.title || '—'}</td>
                  <td className="px-3 py-2 text-sm">{f.severity || '—'}</td>
                  <td className="px-3 py-2 text-sm">{f.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="rounded-xl border border-cyan-500/40 bg-slate-900/60 p-6 backdrop-blur">
        <h2 className="text-lg font-semibold text-cyan-400 mb-2">Cryptographic Proof of Integrity</h2>
        <p className="text-slate-400 text-sm mb-4">
          This report is cryptographically sealed. Scanning this QR code verifies the exact microsecond timestamp and HTTP payloads of all findings against the central Rust orchestrator.
        </p>
        {cryptoProof?.audit_root_hash ? (
          <div className="flex flex-wrap items-start gap-6">
            {cryptoProof.qr_data_url && (
              <img
                src={cryptoProof.qr_data_url}
                alt="QR verification"
                className="w-40 h-40 rounded border border-slate-600 bg-white p-1"
              />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-slate-300 text-sm break-all font-mono">
                <strong className="text-cyan-400">Audit Root Hash (SHA-256):</strong><br />
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
                    Verify: {cryptoProof.verification_url}
                  </a>
                </p>
              )}
            </div>
          </div>
        ) : (
          <p className="text-slate-500 text-sm">
            No sealed run for this client yet. Run a scan to generate the audit trail.
          </p>
        )}
      </section>
    </div>
  )
}
