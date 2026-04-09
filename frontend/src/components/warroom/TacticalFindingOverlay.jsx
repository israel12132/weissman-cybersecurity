import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useWarRoom } from '../../context/WarRoomContext'
import { useClient } from '../../context/ClientContext'
import { X, Copy, Check } from 'lucide-react'

export default function TacticalFindingOverlay() {
  const { lastFinding, setLastFinding } = useWarRoom()
  const { selectedClientId } = useClient()
  const [copied, setCopied] = useState(false)

  const visible = lastFinding && String(lastFinding.client_id) === String(selectedClientId)
  if (!visible || !lastFinding) return null

  const severityColor = {
    critical: 'text-red-400 border-red-500/50 bg-red-950/30',
    high: 'text-orange-400 border-orange-500/50 bg-orange-950/20',
    medium: 'text-amber-400 border-amber-500/50 bg-amber-950/20',
    low: 'text-cyan-400 border-cyan-500/50 bg-cyan-950/20',
  }[lastFinding.severity?.toLowerCase()] || 'text-white/80 border-white/20 bg-black/40'

  const pocSealed =
    lastFinding.poc_sealed ||
    (typeof lastFinding.poc_exploit === 'string' && lastFinding.poc_exploit.includes('[SEALED'))

  const copyProof = () => {
    if (!lastFinding.poc_exploit || pocSealed) return
    navigator.clipboard.writeText(lastFinding.poc_exploit)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  let cve = ''
  try {
    const desc = lastFinding.description || ''
    const match = desc.match(/CVE-\d{4}-\d+/i)
    if (match) cve = match[0]
  } catch (_) {}

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        className="fixed top-20 left-1/2 -translate-x-1/2 z-[100] w-full max-w-xl px-4"
      >
        <div className="rounded-xl border bg-slate-950/95 backdrop-blur-md shadow-2xl overflow-hidden border-white/10">
          <div className="flex items-center justify-between px-4 py-2 border-b border-white/10 bg-black/30">
            <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider">
              Live finding — backend confirmed
            </span>
            <button
              type="button"
              onClick={() => setLastFinding(null)}
              className="p-1.5 rounded-lg text-white/60 hover:text-white hover:bg-white/10 transition-colors"
              aria-label="Dismiss"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex items-start gap-2 flex-wrap">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${severityColor} border`}>
                {lastFinding.severity || '—'}
              </span>
              {cve && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono text-white/70 bg-white/10">
                  {cve}
                </span>
              )}
            </div>
            <p className="text-sm font-medium text-white">
              {lastFinding.title || 'Finding'}
            </p>
            {lastFinding.poc_exploit && (
              <div className="rounded-lg bg-black/60 border border-white/10 p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-[#22d3ee] uppercase tracking-wider">
                    Zero false-positive proof (cURL / payload)
                  </span>
                  {!pocSealed && (
                    <button
                      type="button"
                      onClick={copyProof}
                      className="flex items-center gap-1 text-[10px] font-mono text-white/60 hover:text-[#22d3ee] transition-colors"
                    >
                      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  )}
                </div>
                {pocSealed ? (
                  <p className="text-[11px] text-amber-400/90 m-0">
                    Sealed exploit evidence — open <strong>Findings</strong> and use «Decrypt Exploit Evidence» in the
                    Digital Evidence HUD (audit logged).
                  </p>
                ) : (
                  <pre className="text-[11px] font-mono text-[#4ade80]/90 whitespace-pre-wrap break-all overflow-x-auto max-h-32 overflow-y-auto m-0">
                    {lastFinding.poc_exploit}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
