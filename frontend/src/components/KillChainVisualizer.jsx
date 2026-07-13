import { useTranslation } from 'react-i18next'

const NS = 'components.intelWidgets.killChainVisualizer'

const PHASES = [
  { id: 'recon' },
  { id: 'delivery' },
  { id: 'exploitation' },
]

export default function KillChainVisualizer() {
  const { t } = useTranslation()

  return (
    <div className="kill-chain-visualizer">
      <div className="text-cyber-cyan font-semibold text-xs tracking-widest mb-3 uppercase">
        {t(`${NS}.title`)}
      </div>
      <div className="flex flex-col gap-2">
        {PHASES.map((phase, i) => {
          const isActive = false
          const isPast = false
          return (
            <div
              key={phase.id}
              className={`step-item font-mono text-xs py-2 px-3 rounded border transition-all duration-500 ${
                isActive
                  ? 'border-cyber-cyan bg-cyber-cyan/10 text-cyber-cyan shadow-[0_0_12px_rgba(0,243,255,0.3)]'
                  : isPast
                    ? 'border-cyber-cyan/40 bg-cyber-cyan/5 text-cyber-cyan/80'
                    : 'border-white/10 bg-white/5 text-[var(--text-muted)]'
              }`}
            >
              <span className="tabular-nums text-[var(--text-muted)] mr-2">0{i + 1}</span>
              {t(`${NS}.phases.${phase.id}`)}
              {isActive && <span className="ml-1 animate-pulse">▸</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}
