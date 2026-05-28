import React, { useCallback, useMemo, useState } from 'react'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const PROBE_TYPES = [
  { id: 'generic', label: 'Generic' },
  { id: 'blind_ssrf', label: 'Blind SSRF' },
  { id: 'blind_xss', label: 'Blind XSS' },
  { id: 'blind_xxe', label: 'Blind XXE' },
  { id: 'log4shell', label: 'Log4Shell' },
]

export default function OobVerification() {
  const [targetUrl, setTargetUrl] = useState('')
  const [probeType, setProbeType] = useState('generic')
  const [label, setLabel] = useState('')
  const [minting, setMinting] = useState(false)
  const [polling, setPolling] = useState(false)
  const [probe, setProbe] = useState(null)
  const canMint = useMemo(() => !!String(targetUrl || '').trim(), [targetUrl])

  const mint = useCallback(async () => {
    if (!canMint) return
    setMinting(true)
    try {
      const r = await apiFetch('/api/oast/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          probe_type: probeType,
          label: label.trim() || undefined,
        }),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(data?.error || data?.detail || 'Mint failed')
      setProbe(data)
    } finally {
      setMinting(false)
    }
  }, [canMint, targetUrl, probeType, label])

  const poll = useCallback(async () => {
    const token = probe?.token
    if (!token) return
    setPolling(true)
    try {
      const r = await apiFetch(`/api/oast/verify/${token}`)
      const data = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(data?.error || data?.detail || 'Poll failed')
      setProbe((prev) => ({ ...(prev || {}), ...data }))
    } finally {
      setPolling(false)
    }
  }, [probe?.token])

  return (
    <PageShell
      title="OOB Verification"
      badge="OAST"
      badgeColor="#22d3ee"
      subtitle="Mint a per-test unique token, inject it into probes, and confirm compromise via DNS/HTTP callbacks."
    >
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
          <div>
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Mint Token</h3>
            <p className="text-[11px] text-white/30 mt-1">
              Produces a UUID-backed token bound to this run. Use the callback domain in any field that may trigger
              outbound requests (SSRF, XXE, RCE callbacks). Verification is zero-false-positive when a hit is observed.
            </p>
          </div>

          <div className="space-y-3">
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Target URL (e.g. https://app.target.com)"
              className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
            />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <select
                value={probeType}
                onChange={(e) => setProbeType(e.target.value)}
                className="rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[12px] text-white/70 focus:outline-none focus:border-cyan-500/40"
              >
                {PROBE_TYPES.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Label (optional)"
                className="rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
              />
            </div>

            <button
              type="button"
              disabled={!canMint || minting}
              onClick={mint}
              className="w-full rounded-xl border border-cyan-500/30 text-cyan-300/70 text-[12px] font-mono uppercase px-4 py-2 hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {minting ? '⟳ Minting…' : '+ Mint OOB Token'}
            </button>
          </div>
        </div>

        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Verification</h3>
              <p className="text-[11px] text-white/30 mt-1">
                Poll the token to confirm whether the OAST listener observed DNS/HTTP interactions.
              </p>
            </div>
            <a
              href="/oast"
              className="text-[11px] font-mono text-cyan-300/70 hover:text-cyan-200 underline"
            >
              Full Dashboard →
            </a>
          </div>

          {!probe?.token ? (
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-[11px] font-mono text-white/25">Mint a token to begin.</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="rounded-xl border border-white/10 bg-white/5 p-4 space-y-2">
                <div className="text-[11px] font-mono text-cyan-400/80 break-all">{probe.token}</div>
                <div className="text-[10px] font-mono text-white/30 break-all">
                  Callback domain: <span className="text-cyan-300/70">{probe.callback_domain || '—'}</span>
                </div>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    probe.oob_confirmed
                      ? 'border-green-500/30 text-green-400 bg-green-900/10'
                      : 'border-white/10 text-white/30'
                  }`}>
                    {probe.oob_confirmed ? '✓ HIT CONFIRMED' : `${probe.hit_count ?? 0} hits`}
                  </span>
                  <button
                    type="button"
                    disabled={polling}
                    onClick={poll}
                    className="text-[10px] font-mono border border-white/10 text-white/30 hover:text-white/60 hover:border-white/20 px-2 py-0.5 rounded transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {polling ? '⟳ Polling…' : 'Poll'}
                  </button>
                </div>
                {probe.first_hit_at && (
                  <div className="text-[10px] text-green-400/70">
                    First hit: {new Date(probe.first_hit_at).toLocaleString()}
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <p className="text-[11px] text-white/35">
                  In reports, findings that confirm via OOB callbacks are labeled <span className="font-mono">verification_method=oob_oast_callback</span>.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}

