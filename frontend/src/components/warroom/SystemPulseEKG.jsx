import React, { useEffect, useRef, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, ReferenceLine } from 'recharts'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { apiFetch } from '../../lib/apiBase'

export default function SystemPulseEKG() {
  const { selectedClient } = useClient()
  const { latencyHistory, addLatency, setLastLatencyMs, resetLatencyHistory } = useWarRoom()
  const intervalRef = useRef(null)
  const hadSuccessRef = useRef(false)
  const [probePending, setProbePending] = useState(false)

  const targetUrl = useMemo(() => {
    if (!selectedClient) return null
    let list = []
    const raw = selectedClient.domains
    if (Array.isArray(raw)) {
      list = raw.map(String).filter(Boolean)
    } else if (typeof raw === 'string') {
      try {
        const arr = JSON.parse(raw)
        list = Array.isArray(arr) ? arr.map(String).filter(Boolean) : []
      } catch (_) {
        list = []
      }
    }
    const first = list[0] || null
    if (!first) return null
    return first.startsWith('http') ? first : `https://${first}`
  }, [selectedClient])

  useEffect(() => {
    if (!targetUrl) {
      hadSuccessRef.current = false
      setProbePending(false)
      if (setLastLatencyMs) setLastLatencyMs(null)
      if (resetLatencyHistory) resetLatencyHistory()
      return
    }
    hadSuccessRef.current = false
    if (resetLatencyHistory) resetLatencyHistory()
    setProbePending(true)
    const probe = async () => {
      try {
        const r = await apiFetch('/api/latency-probe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
        })
        const data = await r.json().catch(() => ({}))
        const ms = data.latency_ms
        const value = ms == null || data.error ? null : ms
        if (value != null && value > 0) hadSuccessRef.current = true
        addLatency(value)
        if (setLastLatencyMs) setLastLatencyMs(value)
        setProbePending(false)
      } catch (_) {
        addLatency(null)
        if (setLastLatencyMs) setLastLatencyMs(null)
        setProbePending(false)
      }
    }
    probe()
    intervalRef.current = setInterval(() => {
      setProbePending(true)
      probe()
    }, 2000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [targetUrl, addLatency, setLastLatencyMs, resetLatencyHistory])

  const data = useMemo(() => {
    return latencyHistory.map((d, i) => ({
      index: i,
      ms: d.ms == null ? 0 : d.ms,
      flatline: d.ms == null,
    }))
  }, [latencyHistory])

  const recentBad =
    data.length > 0 && data.slice(-10).every((d) => d.flatline || d.ms === 0)
  /** Pre-filled null history used to falsely show FLATLINE before any probe ran. */
  const hasFlatline = Boolean(targetUrl && hadSuccessRef.current && recentBad && !probePending)
  const showUnreachable = Boolean(targetUrl && !probePending && recentBad && !hadSuccessRef.current)

  return (
    <motion.div
      className="rounded-xl bg-black/60 backdrop-blur border border-white/10 p-2 h-[72px]"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex items-center justify-between mb-1 px-1">
        <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider">
          System pulse
        </span>
        {probePending && targetUrl && (
          <motion.span
            className="text-[10px] font-mono text-cyan-400/90"
            animate={{ opacity: [0.7, 1, 0.7] }}
            transition={{ repeat: Infinity, duration: 1.2 }}
          >
            Scanning…
          </motion.span>
        )}
        {!targetUrl && !probePending && (
          <span className="text-[10px] font-mono text-slate-500">No domain · add target URL</span>
        )}
        {showUnreachable && (
          <span className="text-[10px] font-mono text-amber-400/95" title="latency-probe returned no RTT (TLS, block, or bad URL)">
            Target unreachable
          </span>
        )}
        {hasFlatline && (
          <motion.span
            className="text-[10px] font-mono text-red-400"
            animate={{ opacity: [1, 0.4, 1] }}
            transition={{ repeat: Infinity, duration: 1.5 }}
          >
            Signal lost
          </motion.span>
        )}
      </div>
      <ResponsiveContainer width="100%" height={44}>
        <LineChart data={data} margin={{ top: 2, right: 4, left: 4, bottom: 0 }}>
          <XAxis dataKey="index" hide />
          <YAxis domain={[0, 'auto']} hide />
          <ReferenceLine y={0} stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
          <Line
            type="monotone"
            dataKey="ms"
            stroke={hasFlatline ? '#ef4444' : showUnreachable ? '#fbbf24' : '#22d3ee'}
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={true}
            animationDuration={300}
          />
        </LineChart>
      </ResponsiveContainer>
    </motion.div>
  )
}
