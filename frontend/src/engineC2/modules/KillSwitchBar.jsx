import { useTranslation } from 'react-i18next'
import { useEngineC2Control } from '../EngineC2Boundary'
import Button from '../../components/ui/Button'

export default function KillSwitchBar({ className = '' }) {
  const { t } = useTranslation()
  const { killSwitchEnabled, killed, killReason, triggerKill, resetKill } = useEngineC2Control()

  if (!killSwitchEnabled) return null

  return (
    <div
      className={`flex flex-wrap items-center gap-3 rounded-xl border px-4 py-2 mb-4 ${
        killed
          ? 'border-rose-500/50 bg-rose-950/40'
          : 'border-amber-500/30 bg-amber-950/20'
      } ${className}`}
      role="region"
      aria-label={t('engineC2.kill_switch_region')}
    >
      <span className="text-[10px] font-mono uppercase tracking-widest text-amber-200/80">
        {t('engineC2.c2_armed')}
      </span>
      {killed ? (
        <>
          <span className="text-[11px] font-mono text-rose-300">
            {t('engineC2.killed')} — {killReason}
          </span>
          <Button variant="unstyled"
            type="button"
            onClick={resetKill}
            className="ml-auto px-3 py-1 rounded-lg border border-white/15 text-[10px] font-mono uppercase text-white/70 hover:bg-white/5"
          >
            {t('engineC2.reset_kill')}
          </Button>
        </>
      ) : (
        <Button variant="unstyled"
          type="button"
          onClick={() => triggerKill('operator_emergency_stop')}
          className="ml-auto px-4 py-1.5 rounded-lg border border-rose-500/40 bg-rose-900/30 text-[10px] font-mono uppercase text-rose-200 hover:bg-rose-900/50 transition-colors"
        >
          {t('engineC2.emergency_stop')}
        </Button>
      )}
    </div>
  )
}
