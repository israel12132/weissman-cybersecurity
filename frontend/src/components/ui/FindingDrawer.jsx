import React, { useEffect } from 'react'

/**
 * Right-side drawer that shows the full evidence for a single finding.
 *
 * Props:
 *  - finding   — the full finding object (mitre_attack, remediation, raw, compliance, …)
 *  - onClose   — called when the user clicks the overlay or presses Escape
 *
 * Renders nothing when `finding` is null.
 */
export default function FindingDrawer({ finding, onClose }) {
  useEffect(() => {
    if (!finding) return undefined
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    // Trap scroll on body while drawer is open.
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [finding, onClose])

  if (!finding) return null

  const sev = (finding.severity || 'info').toLowerCase()
  const sevColor = {
    critical: 'text-rose-400 border-rose-500/40 bg-rose-500/10',
    high:     'text-orange-300 border-orange-500/40 bg-orange-500/10',
    medium:   'text-yellow-300 border-yellow-500/40 bg-yellow-500/10',
    low:      'text-blue-300 border-blue-500/40 bg-blue-500/10',
    info:     'text-slate-300 border-slate-600/40 bg-slate-700/10',
  }[sev] || 'text-slate-300 border-slate-600/40 bg-slate-700/10'

  const compliance = Array.isArray(finding.compliance) ? finding.compliance : []
  const cve = finding.cve || finding.cve_id

  return (
    <div className="fixed inset-0 z-[9000] flex">
      <button
        type="button"
        onClick={onClose}
        className="flex-1 bg-black/70 backdrop-blur-sm"
        aria-label="Close drawer"
      />
      <div
        className="w-full max-w-xl h-full bg-[#0b1120] border-s border-white/10 overflow-y-auto"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
      >
        <div className="sticky top-0 bg-[#0b1120]/95 backdrop-blur border-b border-white/10 px-6 py-4 flex items-start justify-between gap-3 z-10">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`inline-block px-2 py-0.5 rounded border uppercase tracking-wider text-[10px] font-mono ${sevColor}`}>
                {sev}
              </span>
              {finding.mitre_attack && (
                <a
                  href={`https://attack.mitre.org/techniques/${String(finding.mitre_attack).replace('.', '/')}`}
                  target="_blank" rel="noopener noreferrer"
                  className="text-[10px] font-mono text-cyan-300 hover:underline"
                >
                  MITRE {finding.mitre_attack}
                </a>
              )}
              {cve && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank" rel="noopener noreferrer"
                  className="text-[10px] font-mono text-cyan-300 hover:underline"
                >
                  {cve}
                </a>
              )}
            </div>
            <h2 id="drawer-title" className="text-base font-semibold text-white truncate">
              {finding.title || finding.type || 'Finding'}
            </h2>
            {finding.target && (
              <p className="text-[11px] font-mono text-white/40 mt-1 truncate">{finding.target}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-white/40 hover:text-white text-2xl leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="p-6 space-y-5 text-sm">
          {finding.description && (
            <section>
              <h3 className="text-[10px] uppercase tracking-widest font-mono text-white/45 mb-2">Description</h3>
              <p className="text-white/75 leading-relaxed whitespace-pre-wrap">{finding.description}</p>
            </section>
          )}

          {finding.remediation && (
            <section>
              <h3 className="text-[10px] uppercase tracking-widest font-mono text-white/45 mb-2">Remediation</h3>
              <p className="text-white/75 leading-relaxed whitespace-pre-wrap">{finding.remediation}</p>
            </section>
          )}

          {compliance.length > 0 && (
            <section>
              <h3 className="text-[10px] uppercase tracking-widest font-mono text-white/45 mb-2">Compliance impact</h3>
              <div className="flex flex-wrap gap-1.5">
                {compliance.map((tag, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/30 text-cyan-200/80 bg-cyan-500/5"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </section>
          )}

          {(finding.source || finding.discovered_at || finding.status) && (
            <section>
              <h3 className="text-[10px] uppercase tracking-widest font-mono text-white/45 mb-2">Metadata</h3>
              <table className="w-full text-[12px] font-mono">
                <tbody className="divide-y divide-white/5">
                  {[
                    ['Source', finding.source],
                    ['Status', finding.status],
                    ['Discovered', finding.discovered_at ? new Date(finding.discovered_at).toLocaleString() : null],
                    ['Risk score', finding.risk_score],
                    ['CVSS', finding.cvss_score],
                  ].filter(([_, v]) => v != null && v !== '').map(([k, v]) => (
                    <tr key={k}>
                      <td className="py-1.5 pe-3 text-white/35 w-32">{k}</td>
                      <td className="py-1.5 text-white/80 break-all">{String(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {finding.raw && (
            <section>
              <h3 className="text-[10px] uppercase tracking-widest font-mono text-white/45 mb-2">Raw evidence</h3>
              <pre className="bg-black/60 rounded-lg p-3 text-[10px] font-mono text-emerald-300 overflow-x-auto max-h-80 whitespace-pre-wrap">
                {JSON.stringify(finding.raw, null, 2)}
              </pre>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}
