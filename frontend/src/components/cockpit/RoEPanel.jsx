import React from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'

const NS = 'components.cockpitWidgets.roePanel'

export default function RoEPanel() {
  const { t } = useTranslation()
  const { clientConfig, setClientConfig, configLoading } = useClient()
  const isTakeover = (clientConfig?.roe_mode || 'safe_proofs') === 'weaponized_god_mode'

  const handleToggle = () => {
    if (configLoading) return
    const next = isTakeover ? 'safe_proofs' : 'weaponized_god_mode'
    setClientConfig({ roe_mode: next })
  }

  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 transition-all duration-300 hover:border-white/20">
      <div className="text-xs font-semibold text-white/50 uppercase tracking-[0.2em] mb-4">
        {t(`${NS}.title`)}
      </div>
      <div className="flex flex-wrap items-center gap-6">
        <div className="flex flex-col gap-2">
          <span className="text-xs text-white/60">
            {isTakeover
              ? t(`${NS}.takeoverDescription`)
              : t(`${NS}.safeDescription`)}
          </span>
          <button
            type="button"
            onClick={handleToggle}
            disabled={configLoading}
            className={`
              relative px-5 py-2.5 rounded-xl font-semibold text-sm tracking-wide
              transition-all duration-300 min-w-[240px]
              disabled:opacity-50 disabled:cursor-not-allowed border
              ${!isTakeover
                ? 'border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 hover:shadow-[0_0_20px_rgba(34,211,238,0.25)]'
                : 'border-[#ef4444]/50 bg-[#ef4444]/10 text-[#ef4444] hover:bg-[#ef4444]/20 hover:shadow-[0_0_20px_rgba(239,68,68,0.3)]'
              }
            `}
          >
            {!isTakeover ? t(`${NS}.safeButton`) : t(`${NS}.takeoverButton`)}
          </button>
        </div>
      </div>
    </div>
  )
}
