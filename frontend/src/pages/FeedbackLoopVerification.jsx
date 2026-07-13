import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { RefreshCw, CheckCircle2, XCircle, Layers } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonBar } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import Button from '../components/ui/Button'

const DEFAULT_TEMPLATE = 'multi_step_state_chain'

export default function FeedbackLoopVerification() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  useCommandCenterScan(selectedClientId)
  const [templates, setTemplates] = useState([])
  const [selectedId, setSelectedId] = useState(DEFAULT_TEMPLATE)
  const [targetUrl, setTargetUrl] = useState('')
  const [yaml, setYaml] = useState('')
  const [loadingYaml, setLoadingYaml] = useState(false)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const canRun = useMemo(
    () => !!targetUrl.trim() && !!yaml.trim(),
    [targetUrl, yaml],
  )

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useClientTargetPrefill(selectedClientId, clients, setTargetUrl)

  useEffect(() => {
    apiFetch('/api/template-engine/templates')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (!Array.isArray(d)) return
        setTemplates(d)
        const preferred = d.find((tpl) => tpl.id === DEFAULT_TEMPLATE)
        if (preferred) setSelectedId(preferred.id)
        else if (d[0]?.id) setSelectedId(d[0].id)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedId) return
    setLoadingYaml(true)
    setError('')
    apiFetch(`/api/template-engine/templates/${encodeURIComponent(selectedId)}`)
      .then(async (r) => {
        const d = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(d?.error || d?.detail || t('pages.feedbackLoopVerification.load_failed'))
        setYaml(String(d?.yaml || ''))
      })
      .catch((e) => setError(e?.message || t('pages.feedbackLoopVerification.load_failed')))
      .finally(() => setLoadingYaml(false))
  }, [selectedId, t])

  const run = useCallback(async () => {
    if (!canRun) return
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const r = await apiFetch('/api/template-engine/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          template_yaml: yaml,
          max_body_bytes: 200000,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || t('pages.feedbackLoopVerification.run_failed'))
      setResult(d)
    } catch (e) {
      setError(e?.message || t('pages.feedbackLoopVerification.run_failed'))
    } finally {
      setRunning(false)
    }
  }, [canRun, targetUrl, yaml, t])

  const stepFindings = useMemo(() => {
    const steps = Array.isArray(result?.steps) ? result.steps : []
    return steps.map((s, i) => {
      const ok = s?.ok === true || s?.success === true
      return {
        title: s.name || s.step || s.id || `Step ${i + 1}`,
        type: s.type || 'verification_step',
        severity: ok ? 'info' : 'high',
        description: s.message || s.detail || s.error || (ok ? 'Step passed' : 'Step failed'),
        remediation: s.status_code != null ? `HTTP ${s.status_code}` : '',
        component: s.matcher || s.extractor || '',
      }
    })
  }, [result])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(stepFindings, { csvPrefix: 'weissman-feedback-loop' })

  const handleRefresh = useCallback(() => {
    if (result) run()
  }, [result, run])

  const stepCount = Array.isArray(result?.steps) ? result.steps.length : 0
  const passedSteps = Array.isArray(result?.steps)
    ? result.steps.filter((s) => s?.ok === true || s?.success === true).length
    : 0

  return (
    <PageShell
      title={t('pages.feedbackLoopVerification.title')}
      badge={t('pages.feedbackLoopVerification.badge')}
      badgeColor="#a78bfa"
      subtitle={t('pages.feedbackLoopVerification.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={running}
          refreshDisabled={!result}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
            {t('pages.feedbackLoopVerification.chain_runner')}
          </h3>

          {clients.length > 0 && (
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-violet-500/40"
            >
              <option value="">{t('pages.feedbackLoopVerification.select_client')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          )}

          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder={t('pages.feedbackLoopVerification.target_placeholder')}
            className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-violet-500/40"
          />

          <div className="flex items-center gap-3 flex-wrap">
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              disabled={loadingYaml}
              className="flex-1 min-w-[180px] rounded-xl bg-[var(--scrim)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-violet-500/40 disabled:opacity-50"
            >
              {templates.map((tpl) => (
                <option key={tpl.id} value={tpl.id}>{tpl.name || tpl.id}</option>
              ))}
              {templates.length === 0 && (
                <option value={DEFAULT_TEMPLATE}>{DEFAULT_TEMPLATE}</option>
              )}
            </select>
            <Button variant="unstyled"
              type="button"
              disabled={!canRun || running || loadingYaml}
              onClick={run}
              className="px-4 py-2 rounded-xl border border-violet-500/30 text-violet-300/70 text-[12px] font-mono uppercase hover:bg-violet-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {running ? t('pages.feedbackLoopVerification.running') : t('pages.feedbackLoopVerification.run_chain')}
            </Button>
          </div>

          {templates.length === 0 && (
            <p className="text-[11px] text-amber-300/70 font-mono">
              {t('pages.feedbackLoopVerification.templates_empty')}
            </p>
          )}

          {error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
              {error}
            </div>
          )}

          <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[10px] font-mono text-[var(--text-disabled)]">
                {t('pages.feedbackLoopVerification.template_editable')}
              </div>
              {loadingYaml && (
                <span className="text-[10px] font-mono text-violet-300/60 flex items-center gap-1">
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  {t('pages.feedbackLoopVerification.loading_template')}
                </span>
              )}
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
                rows={14}
                className="w-full rounded-xl bg-[var(--scrim)] border border-[var(--border-default)] px-3 py-2 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-violet-500/40"
              />
            )}
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
            {t('pages.feedbackLoopVerification.state_evidence')}
          </h3>

          {!result ? (
            <EmptyState
              icon={<Layers className="w-8 h-8 text-[var(--text-disabled)]" />}
              title={t('pages.feedbackLoopVerification.result_empty_title')}
              description={t('pages.feedbackLoopVerification.result_empty')}
            />
          ) : (
            <>
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-3 text-center">
                  <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.feedbackLoopVerification.steps_total')}</div>
                  <div className="text-xl font-semibold text-white">{stepCount}</div>
                </div>
                <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-3 text-center">
                  <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.feedbackLoopVerification.steps_passed')}</div>
                  <div className="text-xl font-semibold text-emerald-300">{passedSteps}</div>
                </div>
                <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-3 text-center">
                  <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.feedbackLoopVerification.verification')}</div>
                  <div className="flex items-center justify-center gap-1 mt-1">
                    {result?.verification?.verified ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                        <span className="text-[11px] font-mono text-green-400">{t('pages.feedbackLoopVerification.verified')}</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="w-4 h-4 text-[var(--text-muted)]" />
                        <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.feedbackLoopVerification.not_verified')}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {result?.verification?.message && (
                <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] px-3 py-2 text-[11px] text-[var(--text-tertiary)] font-mono">
                  {String(result.verification.message)}
                </div>
              )}
            </>
          )}

          <WeissmanFindingsPanel
            findings={stepFindings}
            filteredFindings={filteredFindings}
            counts={counts}
            total={total}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={running && !stepFindings.length}
            accent="#a78bfa"
            title={t('pages.feedbackLoopVerification.state_evidence')}
            showEmptyReady={!result && !running}
            emptyReadyTitle={t('pages.feedbackLoopVerification.result_empty_title')}
            emptyReadyBody={t('pages.feedbackLoopVerification.result_empty')}
            renderFinding={(f, i) => (
              <div key={i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2 space-y-1">
                <div className="flex items-start gap-2">
                  <span
                    className={`text-[9px] font-mono uppercase shrink-0 ${f.severity === 'info' ? 'text-emerald-300' : 'text-orange-300'}`}
                  >
                    [{f.severity}]
                  </span>
                  <span className="text-[12px] font-mono text-[var(--text-primary)] min-w-0">{f.title}</span>
                  {f.type && (
                    <span className="text-[9px] font-mono text-[var(--text-muted)] border border-[var(--border-default)] px-1.5 py-0.5 rounded shrink-0">
                      {f.type}
                    </span>
                  )}
                </div>
                {f.description && (
                  <p className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">{f.description}</p>
                )}
                {(f.remediation || f.component) && (
                  <div className="flex flex-wrap gap-2 text-[9px] font-mono text-[var(--text-disabled)]">
                    {f.remediation && <span>{f.remediation}</span>}
                    {f.component && <span>{f.component}</span>}
                  </div>
                )}
              </div>
            )}
          />
        </div>
      </div>
    </PageShell>
  )
}
