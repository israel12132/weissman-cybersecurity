import React, { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Braces, FlaskConical, Loader2, Play, Trash2 } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import CopyButton from '../components/ui/CopyButton'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { useInsideEngineC2, useC2AbortSignal } from '../engineC2/EngineC2Boundary'
import AstTreeViewer from '../engineC2/modules/AstTreeViewer'
import { useResolvedEngineManifest } from '../engineC2/EngineManifestContext'
import { useLocation } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

const PRESETS = [
  { id: 'json', value: '{"id":1,"name":"alice","enabled":true,"tags":["a","b"]}' },
  { id: 'array', value: '[{"role":"admin"},{"role":"user"},{"role":"guest"}]' },
  { id: 'form', value: 'username=admin&password=secret&remember=1&role=user' },
]

const MAX_LIMIT = 2000

function classifyPayload(text) {
  const s = String(text || '').trim()
  if (!s) return 'empty'
  try {
    JSON.parse(s)
    return 'json'
  } catch {
    return 'raw'
  }
}

export default function AstFuzzingStudio() {
  const { t } = useTranslation()
  return (
    <PageShell
      title={t('pages.astFuzzingStudio.title')}
      badge={t('pages.astFuzzingStudio.badge')}
      badgeColor="#f59e0b"
      subtitle={t('pages.astFuzzingStudio.subtitle')}
    >
      <AstFuzzingStudioBody />
    </PageShell>
  )
}

function AstFuzzingStudioBody() {
  useInsideEngineC2()
  const { pathname } = useLocation()
  const manifest = useResolvedEngineManifest({ pathname })
  const maxAstNodes = manifest?.capabilities?.max_ast_nodes ?? 50_000
  const { t } = useTranslation()
  const { signal, killed } = useC2AbortSignal()
  const [payload, setPayload] = useState(PRESETS[0].value)
  const [maxMutations, setMaxMutations] = useState(200)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const canRun = useMemo(() => !!String(payload || '').trim(), [payload])
  const payloadKind = useMemo(() => classifyPayload(payload), [payload])

  const run = useCallback(async () => {
    if (!canRun || killed) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const clamped = Math.min(Math.max(Number(maxMutations) || 200, 1), MAX_LIMIT)
      const r = await apiFetch('/api/fuzz/ast-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, max_mutations: clamped }),
        signal,
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || t('pages.astFuzzingStudio.preview_failed'))
      setResult(d)
    } catch (e) {
      setError(e?.message || t('pages.astFuzzingStudio.preview_failed'))
    } finally {
      setLoading(false)
    }
  }, [canRun, payload, maxMutations, t, signal, killed])

  const mutations = useMemo(() => (Array.isArray(result?.mutations) ? result.mutations : []), [result])

  const mutationFindings = useMemo(() => mutations.map((m, i) => ({
    title: `Mutation ${i + 1}`,
    type: 'ast_mutation',
    severity: 'info',
    description: String(m),
  })), [mutations])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(mutationFindings, { csvPrefix: 'weissman-ast-mutations' })

  const handleRefresh = useCallback(() => {
    if (result) run()
  }, [result, run])

  const allText = useMemo(() => mutations.join('\n'), [mutations])

  return (
    <>
      <div className="flex justify-end mb-4">
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={loading}
          refreshDisabled={!result}
          exportDisabled={!filteredFindings.length}
        />
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Input panel */}
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest flex items-center gap-2">
              <Braces className="w-3.5 h-3.5 text-amber-300/70" />
              {t('pages.astFuzzingStudio.input')}
            </h3>
            <span
              className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
              style={
                payloadKind === 'json'
                  ? { color: '#34d399', borderColor: '#34d39940', background: '#34d39912' }
                  : { color: '#fbbf24', borderColor: '#fbbf2440', background: '#fbbf2412' }
              }
            >
              {payloadKind === 'json'
                ? t('pages.astFuzzingStudio.json_valid')
                : t('pages.astFuzzingStudio.json_invalid')}
            </span>
          </div>

          <p className="text-[11px] text-white/35 leading-relaxed">{t('pages.astFuzzingStudio.input_hint')}</p>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono text-white/30 uppercase tracking-widest">
              {t('pages.astFuzzingStudio.presets_label')}
            </span>
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setPayload(p.value)}
                className="px-2 py-1 rounded-md text-[10px] font-mono border border-white/10 text-white/55 hover:text-amber-200 hover:border-amber-500/30 transition-colors"
              >
                {t(`pages.astFuzzingStudio.preset_${p.id}`)}
              </button>
            ))}
          </div>

          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={12}
            spellCheck={false}
            className="w-full rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[11px] text-white/75 font-mono focus:outline-none focus:border-amber-500/40 ltr-only"
          />

          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-[11px] font-mono text-white/40 flex items-center gap-2">
              {t('pages.astFuzzingStudio.max_mutations')}
              <input
                type="number"
                min={1}
                max={MAX_LIMIT}
                value={maxMutations}
                onChange={(e) => setMaxMutations(e.target.value)}
                className="w-24 rounded-lg bg-black/60 border border-white/10 px-2 py-1 text-[11px] text-white/75 font-mono focus:outline-none focus:border-amber-500/40"
              />
            </label>
            <button
              type="button"
              disabled={!canRun || loading}
              onClick={run}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-amber-500/30 text-amber-300/80 text-[12px] font-mono uppercase hover:bg-amber-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              {loading ? t('pages.astFuzzingStudio.generating') : t('pages.astFuzzingStudio.generate')}
            </button>
            {payload && (
              <button
                type="button"
                onClick={() => setPayload('')}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl border border-white/10 text-white/45 text-[12px] font-mono hover:text-white/80 transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" />
                {t('pages.astFuzzingStudio.clear')}
              </button>
            )}
          </div>

          {error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
              {error}
            </div>
          )}
        </div>

        {/* Output panel */}
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest flex items-center gap-2">
              <FlaskConical className="w-3.5 h-3.5 text-amber-300/70" />
              {t('pages.astFuzzingStudio.mutations')}
            </h3>
            {mutations.length > 0 && (
              <CopyButton value={allText} size="md" label={t('pages.astFuzzingStudio.copy_all')} />
            )}
          </div>

          <AstTreeViewer
            nodes={mutations}
            maxNodes={maxAstNodes}
            loading={loading && !mutations.length}
            emptyTitle={t('pages.astFuzzingStudio.mutations')}
            emptyBody={t('pages.astFuzzingStudio.preview_empty')}
          />
        </div>
      </div>
    </>
  )
}
