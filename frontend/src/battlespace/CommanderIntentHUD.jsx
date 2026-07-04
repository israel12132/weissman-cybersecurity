import { useTranslation } from 'react-i18next'
import { Crosshair, Ghost, Shield } from 'lucide-react'

export default function CommanderIntentHUD({
  focusNode,
  intentActive,
  onClearFocus,
  onWargame,
  wargaming,
  stripsChain,
  nodeCount,
  edgeCount,
}) {
  const { t } = useTranslation()

  return (
    <div className="battlespace-hud absolute top-3 left-3 right-3 z-10 flex flex-wrap items-start justify-between gap-3 pointer-events-none">
      <div className="pointer-events-auto rounded-xl border border-cyan-500/25 bg-black/70 backdrop-blur-md px-4 py-3 max-w-md">
        <div className="flex items-center gap-2 mb-1">
          <Crosshair className="w-4 h-4 text-cyan-400" />
          <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-200/90">
            {t('battlespace.commander_intent')}
          </span>
        </div>
        {focusNode ? (
          <>
            <p className="text-sm font-semibold text-white truncate">{focusNode.label || focusNode.graph_key}</p>
            <p className="text-[10px] font-mono text-white/45 mt-0.5">
              {focusNode.node_type}
              {focusNode.crown_jewel ? ' · crown jewel' : ''}
              {focusNode.internet_exposed ? ' · perimeter' : ''}
            </p>
            {intentActive && (
              <p className="text-[10px] text-cyan-300/70 mt-2">
                {t('battlespace.path_highlight')}
              </p>
            )}
            <div className="flex flex-wrap gap-2 mt-3">
              <button
                type="button"
                onClick={onWargame}
                disabled={wargaming}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-violet-500/40 bg-violet-500/10 text-[10px] font-mono text-violet-200 hover:bg-violet-500/20 disabled:opacity-50"
              >
                <Ghost className="w-3.5 h-3.5" />
                {t('battlespace.shadow_wargame')}
              </button>
              <button
                type="button"
                onClick={onClearFocus}
                className="px-2.5 py-1 rounded-lg border border-white/15 text-[10px] font-mono text-white/55 hover:text-white/85"
              >
                {t('battlespace.clear_focus')}
              </button>
            </div>
          </>
        ) : (
          <p className="text-[11px] text-white/50">
            {t('battlespace.select_asset')}
          </p>
        )}
      </div>

      <div className="pointer-events-auto rounded-xl border border-white/10 bg-black/60 backdrop-blur-md px-3 py-2 text-[10px] font-mono text-white/50">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-cyan-400/80" />
          <span>{nodeCount.toLocaleString()} nodes · {edgeCount.toLocaleString()} edges</span>
        </div>
        {stripsChain?.reached_goal && (
          <p className="text-emerald-400/80 mt-1">
            STRIPS: {stripsChain.steps?.length ?? 0} steps → {stripsChain.goal}
          </p>
        )}
      </div>
    </div>
  )
}
