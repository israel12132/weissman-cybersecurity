import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle2, XCircle } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EmptyState from '../components/ui/EmptyState'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonBar } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import { useInsideEngineC2, useC2AbortSignal } from '../engineC2/EngineC2Boundary'
import { useClient } from '../context/ClientContext'
import { clientPrimaryTargetUrl } from '../lib/clientTarget'

const NS = 'pages.templateEngineWorkbench'

function CodeBlock({ label, value }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/50 p-4">
      {label && <div className="text-[10px] font-mono text-white/30 mb-2">{label}</div>}
      <pre className="text-[11px] leading-relaxed text-white/70 font-mono whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
        {value}
      </pre>
    </div>
  )
}

export default function TemplateEngineWorkbench() {
  const { t } = useTranslation()
  return (
    <PageShell
      title={t(`${NS}.title`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#60a5fa"
      subtitle={t(`${NS}.subtitle`)}
    >
      <TemplateEngineWorkbenchBody />
    </PageShell>
  )
}

function TemplateEngineWorkbenchBody() {
  useInsideEngineC2()
  const { signal, killed } = useC2AbortSignal()
  const { t } = useTranslation()
  const { selectedClient } = useClient()
  const [templates, setTemplates] = useState([])
  const [selectedId, setSelectedId] = useState('http_baseline')
  const [targetUrl, setTargetUrl] = useState('')
  const [yaml, setYaml] = useState('')
  const [runResult, setRunResult] = useState(null)
  const [loadingYaml, setLoadingYaml] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  const canRun = useMemo(() => !!String(targetUrl || '').trim() && !!String(yaml || '').trim(), [targetUrl, yaml])

  const stepCount = Array.isArray(runResult?.steps) ? runResult.steps.length : 0
  const matchedSteps = Array.isArray(runResult?.steps)
    ? runResult.steps.filter((s) => s?.matched === true).length
    : 0

  useEffect(() => {
    apiFetch('/api/template-engine/templates')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setTemplates(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    const url = clientPrimaryTargetUrl(selectedClient)
    if (url) setTargetUrl((prev) => prev || url)
  }, [selectedClient])

  useEffect(() => {
    setLoadingYaml(true)
    setError('')
    apiFetch(`/api/template-engine/templates/${encodeURIComponent(selectedId)}`)
      .then(async (r) => {
        const d = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(d?.error || t(`${NS}.load_failed`))
        setYaml(String(d?.yaml || ''))
      })
      .catch((e) => setError(e?.message || t(`${NS}.load_failed`)))
      .finally(() => setLoadingYaml(false))
  }, [selectedId, t])

  const run = useCallback(async () => {
    if (!canRun || killed) return
    setRunning(true)
    setError('')
    setRunResult(null)
    try {
      const r = await apiFetch('/api/template-engine/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          template_yaml: yaml,
          max_body_bytes: 200000,
        }),
        signal,
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || t(`${NS}.run_failed`))
      setRunResult(d)
    } catch (e) {
      setError(e?.message || t(`${NS}.run_failed`))
    } finally {
      setRunning(false)
    }
  }, [canRun, targetUrl, yaml, t, signal, killed])

  const loadTemplates = useCallback(() => {
    apiFetch('/api/template-engine/templates')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setTemplates(d) })
      .catch(() => {})
  }, [])

  const listFindings = useMemo(() => [
    ...templates.map((tpl) => ({
      id: tpl.id,
      severity: 'info',
      title: tpl.name || tpl.id,
      type: 'template',
      description: tpl.description || '',
    })),
    ...(Array.isArray(runResult?.steps) ? runResult.steps.map((step) => ({
      id: `run-${step.id}`,
      severity: step.matched ? 'medium' : 'info',
      title: step.id,
      type: 'run_step',
      description: step.matched ? 'matched' : 'no_match',
    })) : []),
  ], [templates, runResult])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-templates',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  const visibleTemplates = useMemo(() => {
    if (!searchQuery.trim()) return templates
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return templates.filter((tpl) => ids.has(String(tpl.id)))
  }, [templates, filteredFindings, searchQuery])

  const visibleRunSteps = useMemo(() => {
    const steps = Array.isArray(runResult?.steps) ? runResult.steps : []
    if (!searchQuery.trim()) return steps
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return steps.filter((step) => ids.has(`run-${step.id}`))
  }, [runResult, filteredFindings, searchQuery])

  return (
    <>
      <div className="flex justify-end mb-4">
        <ShellScanActions
          onRefresh={loadTemplates}
          onExport={exportCsv}
          refreshLoading={loadingYaml}
          exportDisabled={!filteredFindings.length}
        />
      </div>
      <div className="mb-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="space-y-4">
          {templates.length > 0 && (
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleTemplates.length + (runResult ? visibleRunSteps.length : 0)}
              totalCount={listFindings.length}
            />
          )}
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">
              {t(`${NS}.runner`)}
            </h3>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder={t(`${NS}.target_placeholder`)}
              className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-blue-500/40"
            />
            <div className="flex items-center gap-3 flex-wrap">
              <select
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
                className="rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[12px] text-white/70 focus:outline-none focus:border-blue-500/40"
              >
                {visibleTemplates.map((tpl) => (
                  <option key={tpl.id} value={tpl.id}>{tpl.name}</option>
                ))}
                {visibleTemplates.length === 0 && templates.length > 0 && (
                  <option value="" disabled>{t('weissmanFindings.filtered_title')}</option>
                )}
                {templates.length === 0 && <option value="http_baseline">http_baseline</option>}
              </select>
              <button
                type="button"
                disabled={!canRun || running || loadingYaml}
                onClick={run}
                className="px-4 py-2 rounded-xl border border-blue-500/30 text-blue-300/70 text-[12px] font-mono uppercase hover:bg-blue-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {running ? `⟳ ${t(`${NS}.running`)}` : `▶ ${t(`${NS}.run`)}`}
              </button>
            </div>
            {error && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
                {error}
              </div>
            )}
          </div>

          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">
                {t(`${NS}.template_yaml`)}
              </h3>
              <span className="text-[10px] font-mono text-white/25">
                {loadingYaml ? t(`${NS}.loading`) : t(`${NS}.editable`)}
              </span>
            </div>
            {loadingYaml && !yaml ? (
              <div className="space-y-2">
                <SkeletonBar className="h-3 w-full" />
                <SkeletonBar className="h-3 w-5/6" />
                <SkeletonBar className="h-3 w-4/6" />
              </div>
            ) : (
              <textarea
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                rows={18}
                className="w-full rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[11px] text-white/70 font-mono focus:outline-none focus:border-blue-500/40"
              />
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">
              {t(`${NS}.result`)}
            </h3>
            {!runResult ? (
              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <p className="text-[11px] font-mono text-white/25">
                  {t(`${NS}.result_empty`)}
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-xl border border-white/10 bg-white/5 p-3 text-center">
                    <div className="text-[10px] font-mono text-white/40 uppercase">{t(`${NS}.result_status`)}</div>
                    <div className="flex items-center justify-center gap-1 mt-1">
                      {runResult?.verification?.verified ? (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-green-400" />
                          <span className="text-[11px] font-mono text-green-400">{t(`${NS}.verified`)}</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 text-white/40" />
                          <span className="text-[11px] font-mono text-white/40">{t(`${NS}.not_verified`)}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/5 p-3 text-center">
                    <div className="text-[10px] font-mono text-white/40 uppercase">{t(`${NS}.result_matched`)}</div>
                    <div className="text-lg font-semibold mt-1" style={{ color: runResult?.matched ? '#4ade80' : '#f87171' }}>
                      {runResult?.matched ? t(`${NS}.result_matched_yes`) : t(`${NS}.result_matched_no`)}
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/5 p-3 text-center">
                    <div className="text-[10px] font-mono text-white/40 uppercase">{t(`${NS}.result_steps`)}</div>
                    <div className="text-lg font-semibold text-white mt-1">{stepCount}</div>
                    <div className="text-[10px] font-mono text-white/35">
                      {t(`${NS}.steps_matched`, { matched: matchedSteps, total: stepCount })}
                    </div>
                  </div>
                </div>

                {runResult?.verification?.message && (
                  <div className="rounded-xl border border-white/10 bg-black/50 px-3 py-2 text-[11px] text-white/60 font-mono">
                    {String(runResult.verification.message)}
                  </div>
                )}

                {Array.isArray(runResult.steps) && runResult.steps.length > 0 && (
                  <div className="space-y-2">
                    {visibleRunSteps.length === 0 ? (
                      <EmptyState
                        icon="search"
                        title={t('weissmanFindings.filtered_title')}
                        body={t('weissmanFindings.filtered_body')}
                        compact
                      />
                    ) : visibleRunSteps.map((step) => (
                      <div
                        key={step.id}
                        className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 flex items-center justify-between gap-3"
                      >
                        <span className="text-[11px] font-mono text-white/70">{t(`${NS}.step_label`, { id: step.id })}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          step.matched ? 'border-green-500/30 text-green-400 bg-green-900/10' : 'border-white/10 text-white/30'
                        }`}>
                          {step.matched ? t(`${NS}.step_matched`) : t(`${NS}.step_no_match`)}
                        </span>
                        <span className="text-[10px] font-mono text-white/30 shrink-0">
                          {t(`${NS}.duration_ms`, { ms: step.duration_ms ?? 0 })}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                <CodeBlock label={t(`${NS}.verification`)} value={JSON.stringify(runResult.verification || {}, null, 2)} />
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
