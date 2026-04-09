import { useMemo } from 'react'

function GaugeSvg({ score }) {
  const safeScore = Math.min(100, Math.max(0, Number(score) ?? 0))
  const r = 44
  const stroke = 8
  const circumference = 2 * Math.PI * r
  const offset = circumference - (safeScore / 100) * circumference
  const color = safeScore >= 90 ? '#00f5ff' : safeScore >= 70 ? '#ffb800' : '#ff3366'

  return (
    <svg width="120" height="120" viewBox="0 0 120 120" className="gauge-glow mx-auto">
      <circle
        cx="60"
        cy="60"
        r={r}
        fill="none"
        stroke="#1a1a1a"
        strokeWidth={stroke}
      />
      <circle
        cx="60"
        cy="60"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 60 60)"
        className="transition-all duration-700"
      />
      <text
        x="60"
        y="58"
        textAnchor="middle"
        className="text-2xl font-bold fill-[#a0aec0]"
      >
        {Math.round(safeScore)}
      </text>
      <text
        x="60"
        y="72"
        textAnchor="middle"
        className="text-[10px] fill-[#606070]"
      >
        / 100
      </text>
    </svg>
  )
}

export default function SecurityScoreGauge({ data }) {
  const score = useMemo(() => {
    if (data?.score != null) return data.score
    return null
  }, [data])

  return (
    <div className="border border-war-border rounded-lg bg-war-dark p-4">
      <p className="text-war-cyan text-xs font-semibold tracking-wider uppercase mb-2">
        Weissman Security Score
      </p>
      <GaugeSvg score={score ?? 0} />
      <p className="text-[10px] text-war-silver/60 mt-2 text-center">
        CVSS × EPSS × Asset Criticality
      </p>
      {data?.benchmark?.vs_label && (
        <p className="text-[10px] text-war-cyan/90 mt-2 text-center font-medium" title="C-level industry benchmark">
          vs {data.benchmark.sector_name}: {data.benchmark.vs_label}
        </p>
      )}
      {data?.benchmark?.percentile_rank != null && (
        <p className="text-[9px] text-war-silver/70 text-center">
          Percentile vs sectors: {data.benchmark.percentile_rank}%
        </p>
      )}
      {data?.bySeverity && Object.keys(data.bySeverity).length > 0 && (
        <ul className="mt-3 space-y-1 text-[10px]">
          {Object.entries(data.bySeverity).map(([sev, count]) => (
            <li key={sev} className="flex justify-between">
              <span className={sev === 'critical' ? 'text-war-red' : sev === 'high' ? 'text-war-gold' : 'text-war-silver/80'}>
                {sev}
              </span>
              <span>{count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
