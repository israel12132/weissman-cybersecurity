/**
 * Module 5: Quantum Timing Profiler — EKG/Oscilloscope style real-time view.
 * WebSocket stream: baseline (blue) vs payload (red) latency in μs; live Z-Score and confidence %.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts'
import { apiFetch } from '../lib/apiBase'
import StandaloneLabShell from './ui/StandaloneLabShell'
import Button from './ui/Button'

const NS = 'components.tools.quantumTimingProfiler'

const WS_BASE = () => {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}`
}

const MAX_POINTS = 200

export default function QuantumTimingProfiler() {
  const { t } = useTranslation()
  const { clientId } = useParams()
  const [target, setTarget] = useState('')
  const [client, setClient] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [chartData, setChartData] = useState([])
  const [baselineMean, setBaselineMean] = useState(null)
  const [baselineStd, setBaselineStd] = useState(null)
  const [zScore, setZScore] = useState(null)
  const [confidencePct, setConfidencePct] = useState(null)
  const [payloadUsed, setPayloadUsed] = useState('')
  const wsRef = useRef(null)
  const dataRef = useRef([])

  const fetchClient = useCallback(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
        if (c?.domains_json) {
          try {
            const domains = JSON.parse(c.domains_json)
            if (domains?.[0]) setTarget(domains[0])
          } catch (_) {}
        }
      })
      .catch(() => setClient(null))
  }, [clientId])

  useEffect(() => {
    fetchClient()
  }, [fetchClient])

  const startScan = useCallback(() => {
    const url = '/api/timing-scan/run'
    const body = target.trim()
      ? { target: target.trim() }
      : clientId
        ? { client_id: String(clientId) }
        : null
    if (!body) {
      setError(t(`${NS}.no_target_error`))
      return
    }
    setError('')
    setRunning(true)
    setChartData([])
    dataRef.current = []
    setBaselineMean(null)
    setBaselineStd(null)
    setZScore(null)
    setConfidencePct(null)
    setPayloadUsed('')

    apiFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Start failed'))))
      .then((data) => {
        if (data.detail) setError('')
        const wsUrl = `${WS_BASE()}/ws/timing`
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws
        ws.onmessage = (ev) => {
          try {
            const e = JSON.parse(ev.data)
            const idx = e.sample_index ?? dataRef.current.length
            const point = {
              index: idx,
              baseline_us: e.phase === 'baseline' ? e.latency_us : undefined,
              payload_us: e.phase === 'payload' ? e.latency_us : undefined,
            }
            if (e.phase === 'baseline' && e.baseline_mean_us != null) {
              setBaselineMean(e.baseline_mean_us)
              setBaselineStd(e.baseline_std_us ?? 0)
            }
            if (e.phase === 'payload') {
              if (e.z_score != null) setZScore(e.z_score)
              if (e.confidence_pct != null) setConfidencePct(e.confidence_pct)
              if (e.payload_used) setPayloadUsed(String(e.payload_used).slice(0, 80))
            }
            dataRef.current = [...dataRef.current, point].slice(-MAX_POINTS)
            setChartData([...dataRef.current])
          } catch (_) {}
        }
        ws.onclose = () => setRunning(false)
        ws.onerror = () => setRunning(false)
      })
      .catch((e) => {
        setError(e?.message || t(`${NS}.start_failed`))
        setRunning(false)
      })
  }, [target, clientId, t])

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  const chartPoints = chartData.length
    ? chartData
    : [{ index: 0, baseline_us: 0, payload_us: 0 }]

  return (
    <StandaloneLabShell title={t(`${NS}.title`)} subtitle={t(`${NS}.subtitle`)}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-2 rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 p-4">
            <label className="block text-[var(--text-tertiary)] text-xs uppercase tracking-wider mb-2">
              {t(`${NS}.target_label`)}
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={t(`${NS}.target_placeholder`)}
                className="flex-1 rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white placeholder-[var(--text-muted)] focus:ring-2 focus:ring-cyan-500/50"
                disabled={running}
              />
              <Button variant="unstyled"
                onClick={startScan}
                disabled={running}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-[var(--bg-4)] text-white font-medium text-sm"
              >
                {running ? t(`${NS}.scanning`) : t(`${NS}.start_scan`)}
              </Button>
            </div>
            {clientId && (
              <p className="mt-2 text-[var(--text-muted)] text-xs">
                {t(`${NS}.client_id`, { id: clientId })}
                {client?.name && ` ${t(`${NS}.client_name`, { name: client.name })}`}
              </p>
            )}
            {error && (
              <p className="mt-2 text-red-400 text-sm">{error}</p>
            )}
          </div>

          <div className="rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 p-4">
            <div className="text-[var(--text-tertiary)] text-xs uppercase tracking-wider mb-2">
              {t(`${NS}.live_stats`)}
            </div>
            <div className="space-y-2 text-sm">
              {baselineMean != null && (
                <div>
                  <span className="text-[var(--text-muted)]">{t(`${NS}.baseline_mu`)}</span>{' '}
                  <span className="text-cyan-400 font-mono">{baselineMean.toFixed(0)} μs</span>
                </div>
              )}
              {baselineStd != null && baselineStd > 0 && (
                <div>
                  <span className="text-[var(--text-muted)]">{t(`${NS}.baseline_sigma`)}</span>{' '}
                  <span className="text-cyan-400 font-mono">{baselineStd.toFixed(0)} μs</span>
                </div>
              )}
              {zScore != null && (
                <div>
                  <span className="text-[var(--text-muted)]">{t(`${NS}.z_score`)}</span>{' '}
                  <span className={zScore >= 3 ? 'text-red-400 font-bold' : 'text-amber-400 font-mono'}>
                    {zScore.toFixed(2)}
                  </span>
                </div>
              )}
              {confidencePct != null && (
                <div>
                  <span className="text-[var(--text-muted)]">{t(`${NS}.confidence`)}</span>{' '}
                  <span className="text-emerald-400 font-mono">
                    {confidencePct.toFixed(1)}% {confidencePct >= 99 ? t(`${NS}.boolean_true`) : ''}
                  </span>
                </div>
              )}
              {payloadUsed && (
                <div className="text-[var(--text-muted)] text-xs truncate" title={payloadUsed}>
                  {t(`${NS}.payload_label`, { text: payloadUsed })}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">
              {t(`${NS}.oscilloscope_title`)}
            </h2>
            <div className="flex gap-4 text-xs">
              <span className="text-cyan-400">{t(`${NS}.baseline_legend`)}</span>
              <span className="text-red-400">{t(`${NS}.payload_legend`)}</span>
            </div>
          </div>
          <div className="h-[360px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                accessibilityLayer
                data={chartPoints}
                margin={{ top: 8, right: 16, left: 8, bottom: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="index"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  unit=" μs"
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }}
                  labelStyle={{ color: '#e2e8f0' }}
                  formatter={(value) => [value != null ? `${value} μs` : '—', '']}
                />
                <Legend />
                {baselineMean != null && (
                  <ReferenceLine
                    y={baselineMean}
                    stroke="#06b6d4"
                    strokeDasharray="4 4"
                    strokeOpacity={0.6}
                  />
                )}
                <Line
                  type="monotone"
                  dataKey="baseline_us"
                  name={t(`${NS}.chart_baseline`)}
                  stroke="#06b6d4"
                  strokeWidth={2}
                  dot={false}
                  connectNulls
                />
                <Line
                  type="monotone"
                  dataKey="payload_us"
                  name={t(`${NS}.chart_payload`)}
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  connectNulls
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[var(--text-muted)] text-xs mt-2">
            {t(`${NS}.footer`)}
          </p>
        </div>
    </StandaloneLabShell>
  )
}
