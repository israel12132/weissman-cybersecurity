import { useTranslation } from 'react-i18next'
import LiveCounter from './LiveCounter'

const NS = 'components.intelWidgets.globalThreatTicker'

export default function GlobalThreatTicker({ scoreData, intelCount = 0, topologyStats = null }) {
  const { t } = useTranslation()
  const score = scoreData?.score ?? 0
  const critical = (scoreData?.bySeverity && scoreData.bySeverity.critical) || 0
  const high = (scoreData?.bySeverity && scoreData.bySeverity.high) || 0
  const nodes = topologyStats?.nodes ?? 0
  const edges = topologyStats?.edges ?? 0

  return (
    <div className="global-threat-ticker overflow-hidden flex items-center justify-center gap-10 py-2 flex-wrap">
      <span className="font-mono text-xs text-cyber-cyan/90 tracking-wider">
        {t(`${NS}.score`)}: <LiveCounter value={Math.round(score)} className="text-cyber-cyan" />
      </span>
      <span className="font-mono text-xs text-war-red/95 tracking-wider">
        {t(`${NS}.crit`)}: <LiveCounter value={critical} className="text-war-red" />
      </span>
      <span className="font-mono text-xs text-amber-400/90 tracking-wider">
        {t(`${NS}.high`)}: <LiveCounter value={high} className="text-amber-400" />
      </span>
      {nodes > 0 && (
        <span className="font-mono text-xs text-cyan-400/90 tracking-wider">
          {t('battlespace.nodes')}: <LiveCounter value={nodes} className="text-cyan-400" />
        </span>
      )}
      {edges > 0 && (
        <span className="font-mono text-xs text-violet-400/90 tracking-wider">
          {t('battlespace.edges')}: <LiveCounter value={edges} className="text-violet-400" />
        </span>
      )}
      <span className="font-mono text-xs text-slate-400 tracking-wider">
        {t(`${NS}.intel`)}: <LiveCounter value={intelCount} className="text-slate-300" />
      </span>
    </div>
  )
}
