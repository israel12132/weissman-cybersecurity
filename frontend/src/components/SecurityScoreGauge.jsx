import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

const NS = 'components.intelWidgets.securityScoreGauge'

function GaugeSvg({ score }) {
  // Distinguish a genuinely unknown score (null/non-finite) from a real 0: an unknown
  // score must NOT paint a red "0 / 100" gauge implying worst-possible posture.
  const numericScore = Number(score)
  const hasScore = score != null && Number.isFinite(numericScore)
  const safeScore = hasScore ? Math.min(100, Math.max(0, numericScore)) : 0
  const r = 44
  const stroke = 8
  const circumference = 2 * Math.PI * r
  // Unknown → empty ring (full offset), neutral gray, "—".
  const offset = hasScore ? circumference - (safeScore / 100) * circumference : circumference
  const color = !hasScore ? '#3a3a44' : safeScore >= 90 ? '#00f5ff' : safeScore >= 70 ? '#ffb800' : '#ff3366'

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
      {hasScore && (
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
      )}
      <text
        x="60"
        y="58"
        textAnchor="middle"
        className="text-2xl font-bold fill-[#a0aec0]"
      >
        {hasScore ? Math.round(safeScore) : '—'}
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
  const { t } = useTranslation()
  const score = useMemo(() => {
    if (data?.score != null) return data.score
    return null
  }, [data])

  const severityLabel = (sev) => t(`${NS}.severity.${sev}`, { defaultValue: sev })

  return (
    <div className="border border-war-border rounded-lg bg-war-dark p-4">
      <p className="text-war-cyan text-xs font-semibold tracking-wider uppercase mb-2">
        {t(`${NS}.title`)}
      </p>
      <GaugeSvg score={score} />
      <p className="text-[10px] text-war-silver/60 mt-2 text-center">
        {score == null ? t(`${NS}.unavailable`) : t(`${NS}.formula`)}
      </p>
      {data?.benchmark?.vs_label && (
        <p
          className="text-[10px] text-war-cyan/90 mt-2 text-center font-medium"
          title={t(`${NS}.benchmarkTitle`)}
        >
          {t(`${NS}.benchmarkVs`, {
            sector: data.benchmark.sector_name,
            label: data.benchmark.vs_label,
          })}
        </p>
      )}
      {data?.benchmark?.percentile_rank != null && (
        <p className="text-[9px] text-war-silver/70 text-center">
          {t(`${NS}.percentile`, { rank: data.benchmark.percentile_rank })}
        </p>
      )}
      {data?.bySeverity && Object.keys(data.bySeverity).length > 0 && (
        <ul className="mt-3 space-y-1 text-[10px]">
          {Object.entries(data.bySeverity).map(([sev, count]) => (
            <li key={sev} className="flex justify-between">
              <span className={sev === 'critical' ? 'text-war-red' : sev === 'high' ? 'text-war-gold' : 'text-war-silver/80'}>
                {severityLabel(sev)}
              </span>
              <span>{count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
