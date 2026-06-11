import React, { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

export default function AstFuzzingStudio() {
  const { t } = useTranslation()
  const [payload, setPayload] = useState('{"id":1,"name":"alice","enabled":true,"tags":["a","b"]}')
  const [maxMutations, setMaxMutations] = useState(200)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const canRun = useMemo(() => !!String(payload || '').trim(), [payload])

  const run = useCallback(async () => {
    if (!canRun) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const r = await apiFetch('/api/fuzz/ast-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload,
          max_mutations: Number(maxMutations) || 200,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || t('pages.astFuzzingStudio.preview_failed'))
      setResult(d)
    } catch (e) {
      setError(e?.message || t('pages.astFuzzingStudio.preview_failed'))
    } finally {
      setLoading(false)
    }
  }, [canRun, payload, maxMutations, t])

  return (
    <PageShell
      title={t('pages.astFuzzingStudio.title')}
      badge={t('pages.astFuzzingStudio.badge')}
      badgeColor="#f59e0b"
      subtitle={t('pages.astFuzzingStudio.subtitle')}
    >
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">
            {t('pages.astFuzzingStudio.input')}
          </h3>
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={14}
            className="w-full rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[11px] text-white/70 font-mono focus:outline-none focus:border-amber-500/40"
          />
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-[11px] font-mono text-white/30 flex items-center gap-2">
              {t('pages.astFuzzingStudio.max_mutations')}
              <input
                type="number"
                value={maxMutations}
                onChange={(e) => setMaxMutations(e.target.value)}
                className="w-24 rounded-lg bg-black/60 border border-white/10 px-2 py-1 text-[11px] text-white/70 font-mono focus:outline-none focus:border-amber-500/40"
              />
            </label>
            <button
              type="button"
              disabled={!canRun || loading}
              onClick={run}
              className="px-4 py-2 rounded-xl border border-amber-500/30 text-amber-300/70 text-[12px] font-mono uppercase hover:bg-amber-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {loading ? t('pages.astFuzzingStudio.generating') : t('pages.astFuzzingStudio.generate')}
            </button>
          </div>
          {error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
              {error}
            </div>
          )}
        </div>

        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">
            {t('pages.astFuzzingStudio.mutations')}
          </h3>
          {!result ? (
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-[11px] font-mono text-white/25">
                {t('pages.astFuzzingStudio.preview_empty')}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="text-[11px] text-white/35">
                {t('pages.astFuzzingStudio.count')}{' '}
                <span className="font-mono text-amber-300/80">{result.count}</span>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/50 p-3 h-[420px] overflow-auto space-y-2">
                {(result.mutations || []).map((m, i) => (
                  <div key={i} className="text-[11px] font-mono text-white/70 break-words border-b border-white/5 pb-2">
                    {m}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}
