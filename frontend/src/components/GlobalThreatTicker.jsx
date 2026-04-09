import LiveCounter from './LiveCounter'

export default function GlobalThreatTicker({ scoreData, globeData, intelCount = 0 }) {
  const score = scoreData?.score ?? 0
  const critical = (scoreData?.bySeverity && scoreData.bySeverity.critical) || 0
  const high = (scoreData?.bySeverity && scoreData.bySeverity.high) || 0
  const pulses = globeData?.scanPulses?.length ?? 0
  const vulns = globeData?.criticalVulns?.length ?? 0

  return (
    <div className="global-threat-ticker overflow-hidden flex items-center justify-center gap-10 py-2">
      <span className="font-mono text-xs text-cyber-cyan/90 tracking-wider">
        SCORE: <LiveCounter value={Math.round(score)} className="text-cyber-cyan" />
      </span>
      <span className="font-mono text-xs text-war-red/95 tracking-wider">
        CRIT: <LiveCounter value={critical} className="text-war-red" />
      </span>
      <span className="font-mono text-xs text-amber-400/90 tracking-wider">
        HIGH: <LiveCounter value={high} className="text-amber-400" />
      </span>
      <span className="font-mono text-xs text-cyber-cyan/90 tracking-wider">
        PULSES: <LiveCounter value={pulses} className="text-cyber-cyan" />
      </span>
      <span className="font-mono text-xs text-cyber-cyan/90 tracking-wider">
        VULNS: <LiveCounter value={vulns} className="text-cyber-cyan" />
      </span>
      <span className="font-mono text-xs text-slate-400 tracking-wider">
        IT: <LiveCounter value={intelCount} className="text-slate-300" />
      </span>
    </div>
  )
}
