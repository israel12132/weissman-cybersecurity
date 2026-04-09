import React, { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useClient } from '../../context/ClientContext'
import DigitalEvidenceHUD from '../warroom/DigitalEvidenceHUD'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import { apiFetch } from '../../lib/apiBase'

function severityToCvss(severity) {
  if (!severity) return '—'
  const s = String(severity).toLowerCase()
  if (s.includes('critical')) return '9.0–10.0'
  if (s.includes('high')) return '7.0–8.9'
  if (s.includes('medium') || s.includes('med')) return '4.0–6.9'
  if (s.includes('low') || s.includes('info')) return '0.1–3.9'
  return '—'
}

function parseDescription(description, source) {
  if (!description || typeof description !== 'string') return {}
  try {
    const d = JSON.parse(description)
    return {
      footprint: d.footprint ?? '',
      trigger_reason: d.trigger_reason ?? '',
      entropy_map: d.entropy_map ?? [],
      entropy_score: d.entropy_score,
      response_bleed_preview: d.response_bleed_preview ?? '',
      bleed_start_offset: d.bleed_start_offset,
      expected_verification: d.expected_verification ?? '',
      remediation_snippet: d.remediation_snippet ?? d.remediation ?? '',
      generated_patch: d.generated_patch ?? '',
    }
  } catch (_) {
    return { footprint: description }
  }
}

function CopyableBlock({ label, value }) {
  const [copied, setCopied] = useState(false)
  const raw = value || '—'
  const text = raw === '—' ? '—' : sanitizeFindingPlainText(raw)
  const copy = () => {
    if (!text || text === '—') return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="rounded-xl border border-white/10 bg-black/60 overflow-hidden">
      <div className="flex items-center justify-between px-2 py-1.5 border-b border-white/10 bg-black/40">
        <span className="text-[10px] uppercase tracking-wider text-[#6b7280] font-mono">{label}</span>
        <button
          type="button"
          onClick={copy}
          className="text-xs font-medium text-[#22d3ee] hover:text-[#67e8f9] transition-colors"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-3 font-mono text-[11px] text-[#4ade80] whitespace-pre-wrap break-all overflow-x-auto m-0 max-h-48 overflow-y-auto">
        {text}
      </pre>
    </div>
  )
}

const AWAITING_POE = 'Awaiting PoE Synthesis…'

/** Forensic / PoE text is rendered as plain React children (escaped) — never HTML. */
function ExpandedRow({ finding, onClose }) {
  const desc = parseDescription(finding.description, finding.source)
  const proofText = finding.poc_exploit?.trim() ? finding.poc_exploit.trim() : AWAITING_POE
  const forensicContent = desc.response_bleed_preview
    ? `Bleed preview (64-byte window):\n${desc.response_bleed_preview}`
    : Array.isArray(desc.entropy_map) && desc.entropy_map.length > 0
      ? `Entropy map:\n${JSON.stringify(desc.entropy_map, null, 2)}`
      : finding.description && String(finding.description).trim().startsWith('{')
        ? (() => {
            try {
              return JSON.stringify(JSON.parse(finding.description), null, 2)
            } catch (_) {
              return finding.description
            }
          })()
        : finding.description || 'No forensic envelope stored for this finding yet.'
  const crimeScene = desc.footprint || finding.description || 'No crime scene report.'
  const remediation = desc.remediation_snippet?.trim() || '—'
  const generatedPatch = desc.generated_patch?.trim() || ''

  return (
    <tr className="bg-[#0a0a0a]">
      <td colSpan={4} className="p-0 border-b border-[#1a1a1a] align-top">
        <div className="relative p-4">
          <button
            type="button"
            onClick={onClose}
            className="absolute top-2 right-2 text-[#6b7280] hover:text-white text-sm"
            aria-label="Close"
          >
            × Close
          </button>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 min-w-0 pr-20">
            <div>
              <h4 className="text-xs font-semibold text-[#22d3ee] mb-2 uppercase tracking-wider">Forensic Evidence</h4>
              <div className="rounded-xl border border-white/10 bg-black/80 shadow-inner p-3 font-mono text-[11px] text-white/80 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {forensicContent}
              </div>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-[#22d3ee] mb-2 uppercase tracking-wider">Crime Scene Report</h4>
              <div className="rounded-xl border border-white/10 bg-black/80 shadow-inner p-3 font-mono text-[11px] text-white/80 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {crimeScene}
              </div>
            </div>
          </div>
          <div className="px-4 pt-4 space-y-3">
            <h4 className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: '#10b981' }}>
              Recommended Remediation (AI Generated)
            </h4>
            <CopyableBlock label="Remediation / patch" value={remediation} />
            {generatedPatch ? (
              <>
                <h4 className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: '#34d399' }}>
                  Generated Patch (Code / Config Fix)
                </h4>
                <CopyableBlock label="generated_patch" value={generatedPatch} />
              </>
            ) : null}
          </div>
        </div>
        <div className="px-4 pb-4">
          <h4 className="text-xs font-semibold text-[#f87171] mb-2 uppercase tracking-wider">
            Zero False-Positive Proof (cURL / Reproduce)
          </h4>
          <CopyableBlock label="Reproduction payload / command" value={proofText} />
        </div>
      </td>
    </tr>
  )
}

export default function FindingsTab() {
  const { selectedClientId, selectedClient } = useClient()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)
  const [findingsError, setFindingsError] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [evidenceFinding, setEvidenceFinding] = useState(null)

  const fetchFindings = useCallback(async () => {
    if (!selectedClientId) {
      setFindings([])
      setFindingsError(null)
      return
    }
    setLoading(true)
    setFindingsError(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/findings`)
      if (r.ok) {
        const d = await r.json()
        setFindings(Array.isArray(d.findings) ? d.findings : [])
        if (!Array.isArray(d.findings)) {
          setFindingsError('Unexpected findings response from API.')
        }
      } else {
        setFindings([])
        setFindingsError(await formatApiErrorResponse(r))
      }
    } catch (e) {
      setFindings([])
      setFindingsError(e?.message || 'Network error')
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  const openPdf = async () => {
    if (!selectedClientId) return
    const url = `/api/clients/${selectedClientId}/report/pdf`
    try {
      const r = await apiFetch(url)
      const contentType = r.headers.get('Content-Type') || ''
      if (!r.ok) {
        setFindingsError(await formatApiErrorResponse(r))
        return
      }
      if (!contentType.includes('application/pdf')) {
        setFindingsError(`Report endpoint returned unexpected type: ${contentType || 'unknown'}`)
        return
      }
      const blob = await r.blob()
      const disposition = r.headers.get('Content-Disposition') || ''
      const match = disposition.match(/filename="?([^";\n]+)"?/)
      let filename = match ? match[1].trim() : 'Weissman_Report.pdf'
      if (!filename.toLowerCase().endsWith('.pdf')) filename = `${filename.replace(/\.[^.]+$/, '')}.pdf`
      const objectUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objectUrl
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(objectUrl)
    } catch (e) {
      setFindingsError(e?.message || 'Failed to download PDF')
    }
  }

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">Select a client from the sidebar to view findings.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-6">
      {findingsError && (
        <div
          className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200"
          role="alert"
        >
          {findingsError}
        </div>
      )}
      {/* Top: PDF + Attack Chain */}
      <div className="flex justify-end gap-3">
        {selectedClientId && (
          <Link
            to={`/attack-chain/${selectedClientId}`}
            className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-all duration-300"
          >
            View Attack Chain
          </Link>
        )}
        <button
          type="button"
          onClick={openPdf}
          className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 hover:shadow-[0_0_20px_rgba(34,211,238,0.2)] transition-all duration-300"
        >
          GENERATE EXECUTIVE PDF
        </button>
      </div>

      {/* Table */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-white/10 bg-white/5">
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-[#6b7280] font-mono w-24">Severity</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-[#6b7280] font-mono w-28">CVSS</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-[#6b7280] font-mono">Title</th>
                <th className="text-left py-3 px-4 text-[10px] uppercase tracking-wider text-[#6b7280] font-mono w-40">Engine/Source</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[#6b7280]">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && !findingsError && findings.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[#6b7280]">
                    No findings for this client.
                  </td>
                </tr>
              )}
              {!loading && findings.map((f) => (
                <React.Fragment key={f.id}>
                  <tr
                    onClick={() => setEvidenceFinding(f)}
                    className="border-b border-white/10 cursor-pointer transition-colors duration-200 hover:bg-white/5"
                  >
                    <td className="py-2.5 px-4">
                      <span
                        className={`font-medium ${
                          (f.severity || '').toLowerCase().includes('critical')
                            ? 'text-[#f87171]'
                            : (f.severity || '').toLowerCase().includes('high')
                              ? 'text-[#fb923c]'
                              : (f.severity || '').toLowerCase().includes('medium')
                                ? 'text-[#fbbf24]'
                                : 'text-[#9ca3af]'
                        }`}
                      >
                        {f.severity || '—'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-[#9ca3af] font-mono text-xs">
                      {severityToCvss(f.severity)}
                    </td>
                    <td className="py-2.5 px-4 text-white max-w-md truncate" title={sanitizeFindingPlainText(f.title, 500)}>
                      {sanitizeFindingPlainText(f.title, 2000) || '—'}
                    </td>
                    <td className="py-2.5 px-4 text-[#22d3ee] font-mono text-xs">
                      {f.source || '—'}
                    </td>
                  </tr>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <DigitalEvidenceHUD clientId={selectedClientId} finding={evidenceFinding} onClose={() => setEvidenceFinding(null)} />
    </div>
  )
}
