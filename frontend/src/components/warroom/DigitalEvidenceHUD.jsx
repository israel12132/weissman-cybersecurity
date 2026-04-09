import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import RuntimeExecutionFlow from '../cockpit/RuntimeExecutionFlow'
import { formatApiErrorFromBody } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import { apiFetch } from '../../lib/apiBase'

function parseDescription(description) {
  if (!description || typeof description !== 'string') return {}
  try {
    const d = JSON.parse(description)
    return {
      footprint: d.footprint ?? '',
      trigger_reason: d.trigger_reason ?? '',
      expected_verification: d.expected_verification ?? '',
      remediation_snippet: d.remediation_snippet ?? d.remediation ?? '',
      generated_patch: d.generated_patch ?? '',
      response_bleed_preview: d.response_bleed_preview ?? '',
      entropy_map: d.entropy_map ?? [],
    }
  } catch (_) {
    return { footprint: description }
  }
}

const AWAITING_POE = 'Awaiting PoE Synthesis…'

function CopyableBlock({ label, value, disableCopy }) {
  const [copied, setCopied] = useState(false)
  const raw = value ?? ''
  const isAwaiting = raw === AWAITING_POE
  const text = isAwaiting ? AWAITING_POE : raw.trim() ? sanitizeFindingPlainText(raw) : ''
  const copy = () => {
    if (disableCopy || !text.trim() || isAwaiting) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="rounded-lg border border-white/10 bg-black/60 overflow-hidden">
      <div className="flex items-center justify-between px-2 py-1 border-b border-white/10">
        <span className="text-[10px] uppercase tracking-wider text-white/50 font-mono">{label}</span>
        {!disableCopy && !isAwaiting && text.trim() ? (
          <button type="button" onClick={copy} className="text-xs text-[#22d3ee] hover:text-[#67e8f9]">
            {copied ? 'Copied' : 'Copy'}
          </button>
        ) : null}
      </div>
      <pre
        className={`p-2 font-mono text-[11px] whitespace-pre-wrap break-all overflow-x-auto m-0 max-h-32 overflow-y-auto ${
          isAwaiting ? 'text-amber-400/90' : 'text-[#4ade80]'
        }`}
      >
        {text || '—'}
      </pre>
    </div>
  )
}

function forensicBody(finding, desc) {
  if (desc.response_bleed_preview) {
    return `Bleed preview:\n${desc.response_bleed_preview}`
  }
  if (Array.isArray(desc.entropy_map) && desc.entropy_map.length > 0) {
    return JSON.stringify(desc.entropy_map, null, 2)
  }
  const raw = finding?.description
  if (raw && typeof raw === 'string' && raw.trim().startsWith('{')) {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2)
    } catch (_) {
      return raw
    }
  }
  if (raw && String(raw).trim()) {
    return String(raw)
  }
  return 'No forensic envelope stored for this finding yet.'
}

function proofCurlText(finding, decryptedCurl) {
  if (decryptedCurl && String(decryptedCurl).trim()) {
    return String(decryptedCurl).trim()
  }
  const p = finding?.poc_exploit
  if (p && String(p).trim()) {
    return String(p).trim()
  }
  return AWAITING_POE
}

export default function DigitalEvidenceHUD({ clientId, finding, onClose }) {
  const [phase, setPhase] = useState('decrypt')
  const [revealIndex, setRevealIndex] = useState(0)
  const [decryptedCurl, setDecryptedCurl] = useState('')
  const [decryptBusy, setDecryptBusy] = useState(false)
  const [decryptErr, setDecryptErr] = useState('')

  const title = sanitizeFindingPlainText(finding?.title || 'Digital Evidence', 500)
  const fullLength = title.length + 20
  const isSealed = Boolean(finding?.poc_sealed)

  useEffect(() => {
    if (!finding) return
    setDecryptedCurl('')
    setDecryptErr('')
    if (finding.poc_sealed) {
      setPhase('sealed_gate')
    } else {
      setPhase('decrypt')
      setRevealIndex(0)
    }
  }, [finding?.id])

  useEffect(() => {
    if (phase !== 'decrypt' || isSealed) return
    const id = setInterval(() => {
      setRevealIndex((i) => {
        if (i >= fullLength) {
          setPhase('revealed')
          return i
        }
        return i + 1
      })
    }, 40)
    return () => clearInterval(id)
  }, [phase, fullLength, isSealed])

  const decryptExploit = async () => {
    if (!clientId || !finding?.id) return
    setDecryptBusy(true)
    setDecryptErr('')
    try {
      const r = await apiFetch(
        `/api/clients/${clientId}/vulnerabilities/${finding.id}/decrypt-poc`,
        { method: 'POST' },
      )
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setDecryptErr(formatApiErrorFromBody(d, r.status))
        return
      }
      setDecryptedCurl(d.poc_exploit || '')
      setPhase('revealed')
    } catch (e) {
      setDecryptErr(String(e.message || e))
    } finally {
      setDecryptBusy(false)
    }
  }

  if (!finding) return null

  const desc = parseDescription(finding.description)
  const proofText = proofCurlText(finding, decryptedCurl)
  const forensicText = sanitizeFindingPlainText(forensicBody(finding, desc))

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-[200] flex items-center justify-center p-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
      >
        <div
          className="absolute inset-0 bg-black/80 backdrop-blur-sm"
          onClick={onClose}
          aria-hidden
        />
        <motion.div
          className="relative w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-2xl border border-[#22d3ee]/40 bg-slate-950/98 shadow-2xl"
          initial={{ scale: 0.7, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 bg-black/40">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-[#22d3ee] uppercase tracking-widest">
                Digital Evidence File
              </span>
              {phase === 'decrypt' && (
                <motion.span
                  className="inline-block w-2 h-2 rounded-full bg-[#22d3ee]"
                  animate={{ opacity: [1, 0.3, 1] }}
                  transition={{ repeat: Infinity, duration: 0.6 }}
                />
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              className="text-white/60 hover:text-white text-lg leading-none px-2 py-1"
              aria-label="Close"
            >
              ×
            </button>
          </div>

          <div className="p-4 overflow-y-auto max-h-[calc(85vh-120px)]">
            {phase === 'decrypt' && !isSealed && (
              <motion.div
                className="font-mono text-sm text-[#22d3ee]/90 mb-4"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
              >
                <span className="text-white/50">DECRYPTING </span>
                <span>{title.slice(0, revealIndex)}</span>
                <motion.span animate={{ opacity: [1, 0] }} transition={{ repeat: Infinity, duration: 0.5 }}>
                  _
                </motion.span>
              </motion.div>
            )}

            {phase === 'sealed_gate' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-4 mb-4"
              >
                <p className="text-sm text-amber-400/90">
                  Exploit evidence is sealed at rest (AES-GCM + commitment + HMAC proof). Decryption is audited.
                </p>
                {finding.poc_commitment_sha256 ? (
                  <div>
                    <h3 className="text-[10px] font-mono text-white/50 uppercase tracking-wider mb-1">
                      SHA-256 commitment (proof of existence)
                    </h3>
                    <pre className="text-[10px] font-mono text-emerald-400/80 break-all bg-black/50 p-2 rounded border border-white/10 m-0">
                      {finding.poc_commitment_sha256}
                    </pre>
                  </div>
                ) : null}
                {decryptErr ? <p className="text-sm text-red-400">{decryptErr}</p> : null}
                <button
                  type="button"
                  disabled={decryptBusy}
                  onClick={decryptExploit}
                  className="w-full py-3 rounded-xl font-semibold text-sm border border-amber-500/60 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25 disabled:opacity-50"
                >
                  {decryptBusy ? 'Decrypting…' : 'Decrypt Exploit Evidence'}
                </button>
              </motion.div>
            )}

            {phase === 'revealed' && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-4"
              >
                <div className="flex gap-2 flex-wrap">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      (finding.severity || '').toLowerCase().includes('critical')
                        ? 'text-red-400 bg-red-500/20'
                        : (finding.severity || '').toLowerCase().includes('high')
                          ? 'text-orange-400 bg-orange-500/20'
                          : 'text-amber-400 bg-amber-500/20'
                    }`}
                  >
                    {finding.severity || '—'}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono text-white/60 bg-white/10">
                    {finding.source || '—'}
                  </span>
                </div>
                <h2 className="text-base font-semibold text-white">{finding.title || '—'}</h2>

                <div>
                  <h3 className="text-[10px] font-mono text-[#22d3ee] uppercase tracking-wider mb-1">
                    Forensic Evidence
                  </h3>
                  <pre className="rounded-lg bg-black/60 p-3 font-mono text-[11px] text-white/80 whitespace-pre-wrap break-all max-h-28 overflow-y-auto m-0">
                    {forensicText}
                  </pre>
                </div>

                <div>
                  <h3 className="text-[10px] font-mono text-[#22d3ee] uppercase tracking-wider mb-1">
                    Zero False-Positive Proof (cURL)
                  </h3>
                  {isSealed && !decryptedCurl ? (
                    <p className="text-xs text-white/50">Use «Decrypt Exploit Evidence» above to reveal the raw command.</p>
                  ) : (
                    <CopyableBlock
                      value={proofText}
                      label="Reproduce"
                      disableCopy={proofText === AWAITING_POE}
                    />
                  )}
                </div>

                {desc.remediation_snippet && (
                  <div>
                    <h3 className="text-[10px] font-mono text-[#10b981] uppercase tracking-wider mb-1">
                      Remediation
                    </h3>
                    <CopyableBlock value={desc.remediation_snippet} label="Patch" />
                  </div>
                )}
                {desc.generated_patch && (
                  <div>
                    <h3 className="text-[10px] font-mono text-[#34d399] uppercase tracking-wider mb-1">
                      Generated Patch
                    </h3>
                    <CopyableBlock value={desc.generated_patch} label="Code" />
                  </div>
                )}
                {clientId && (
                  <div className="mt-3">
                    <RuntimeExecutionFlow clientId={clientId} findingId={finding.finding_id} />
                  </div>
                )}
              </motion.div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
