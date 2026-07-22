import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/apiFetch'

const NS = 'components.cockpitWidgets.severityTrendChart'

function buildArea(values, width, height, padding) {
  if (!values || values.length === 0) {
    return { path: '', linePath: '' }
  }
  const innerW = width - padding * 2
  const innerH = height - padding * 2 - 12
  const max = Math.max(1, ...values)
  const step = innerW / Math.max(1, values.length - 1)
  const points = values.map((v, i) => {
    const x = padding + i * step
    const y = padding + innerH - (v / max) * innerH
    return [x, y]
  })
  const linePath = points
    .map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(' ')
  const firstX = points[0][0].toFixed(1)
  const lastX = points[points.length - 1][0].toFixed(1)
  const baselineY = (padding + innerH).toFixed(1)
  const areaPath = `M${firstX},${baselineY} ${linePath
    .slice(1)} L${lastX},${baselineY} Z`
  return { path: areaPath, linePath, max }
}

export default function SeverityTrendChart({ className = '', height = 180 }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const d = await apiFetch('/api/dashboard/exec-kpis')
        if (!cancelled) setData(d)
      } catch (_) { /* best-effort; non-fatal */ }
      finally { if (!cancelled) setLoading(false) }
    }
    load()
    const timer = setInterval(load, 30_000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [])

  const w = 720
  const h = height
  const padding = 16
  const trend = data?.trend || {}
  const labels = trend.labels || []
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const discovered = trend.discovered || []
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const resolved = trend.resolved || []

  const dArea = useMemo(() => buildArea(discovered, w, h, padding), [discovered, h])
  const rArea = useMemo(() => buildArea(resolved, w, h, padding), [resolved, h])

  const totalDisc = discovered.reduce((a, b) => a + b, 0)
  const totalRes = resolved.reduce((a, b) => a + b, 0)
  const maxY = Math.max(1, dArea.max || 1, rArea.max || 1)

  if (loading && !data) {
    return (
      <section className={`rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-3 ${className}`}>
        <div className="h-44 rounded bg-white/[0.025] animate-pulse" />
      </section>
    )
  }

  return (
    <section
      className={`rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md ${className}`}
      aria-label={t(`${NS}.ariaLabel`)}
    >
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="min-w-0">
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75">
            {t(`${NS}.title`)}
          </h3>
          <p className="text-[10px] font-mono text-white/40 mt-0.5">
            {t(`${NS}.subtitle`)}
          </p>
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono shrink-0">
          <span className="flex items-center gap-1 text-rose-300">
            <span className="w-2 h-2 rounded-full bg-rose-400" /> {t(`${NS}.discovered`, { count: totalDisc })}
          </span>
          <span className="flex items-center gap-1 text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400" /> {t(`${NS}.resolved`, { count: totalRes })}
          </span>
        </div>
      </header>

      <div className="p-2">
        <svg
          viewBox={`0 0 ${w} ${h}`}
          preserveAspectRatio="none"
          width="100%"
          height={h}
          role="img"
          aria-label={t(`${NS}.chartAria`)}
        >
          <defs>
            <linearGradient id="trendDisc" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="#ef4444" stopOpacity="0.45" />
              <stop offset="1" stopColor="#ef4444" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="trendRes" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="#22c55e" stopOpacity="0.40" />
              <stop offset="1" stopColor="#22c55e" stopOpacity="0" />
            </linearGradient>
          </defs>

          {[0.25, 0.5, 0.75].map((p) => {
            const y = padding + (h - padding * 2 - 12) * p
            return (
              <line
                key={p}
                x1={padding}
                x2={w - padding}
                y1={y}
                y2={y}
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="1"
              />
            )
          })}

          {dArea.path && (
            <>
              <path d={dArea.path} fill="url(#trendDisc)" />
              <path d={dArea.linePath} fill="none" stroke="#ef4444" strokeWidth="1.5" strokeLinejoin="round" />
            </>
          )}
          {rArea.path && (
            <>
              <path d={rArea.path} fill="url(#trendRes)" />
              <path d={rArea.linePath} fill="none" stroke="#22c55e" strokeWidth="1.5" strokeLinejoin="round" />
            </>
          )}

          {labels.map((lbl, i) => {
            if (i % 4 !== 0 && i !== labels.length - 1) return null
            const x = padding + (i * (w - padding * 2)) / Math.max(1, labels.length - 1)
            return (
              <text
                key={i}
                x={x}
                y={h - 4}
                fontSize="9"
                fill="rgba(255,255,255,0.35)"
                fontFamily="JetBrains Mono, monospace"
                textAnchor="middle"
              >
                {lbl}
              </text>
            )
          })}

          <text
            x={padding}
            y={padding + 8}
            fontSize="9"
            fill="rgba(255,255,255,0.4)"
            fontFamily="JetBrains Mono, monospace"
          >
            {maxY}
          </text>
        </svg>
      </div>
    </section>
  )
}
