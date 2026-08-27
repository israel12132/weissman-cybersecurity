import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { Trash2 } from 'lucide-react'
import { apiFetch } from '../utils/apiFetch'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { formatApiErrorFromBody } from '../lib/apiError'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'

const SAMPLE_KEYS = ['sample_q1', 'sample_q2', 'sample_q3', 'sample_q4', 'sample_q5']

function fmtCell(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? '✓' : '✗'
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3)
  return String(v)
}

function exportTranscriptCsv(history) {
  const header = ['timestamp', 'question', 'status', 'plan', 'sql', 'row_count', 'elapsed_ms', 'error']
  const rows = history
    .filter((turn) => !turn.pending)
    .map((turn) => [
      turn.t ? new Date(turn.t).toISOString() : '',
      turn.q,
      turn.error ? 'error' : turn.ok ? 'ok' : 'unknown',
      turn.plan,
      turn.sql,
      turn.row_count,
      turn.elapsed_ms,
      turn.error,
    ])
  downloadCsv(rows, header, 'weissman-ask-transcript')
}

function StatusBadge({ ok, error, t }) {
  if (error) {
    return (
      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/15 text-rose-200">
        {t('ask_weissman.status_error')}
      </span>
    )
  }
  if (ok) {
    return (
      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-200">
        {t('ask_weissman.status_ok')}
      </span>
    )
  }
  return (
    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-strong)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)]">
      {t('ask_weissman.status_pending')}
    </span>
  )
}

export default function AskWeissman() {
  const { t } = useTranslation()
  const [question, setQuestion] = useState('')
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const transcriptRef = useRef(null)

  const sampleQuestions = useMemo(
    () => SAMPLE_KEYS.map((key) => t(`ask_weissman.${key}`)),
    [t],
  )

  const completedTurns = useMemo(
    () => history.filter((turn) => !turn.pending),
    [history],
  )

  const transcriptFindings = useMemo(() => completedTurns.map((turn, i) => ({
    id: i,
    severity: turn.error ? 'high' : turn.ok ? 'info' : 'medium',
    title: turn.q,
    type: 'ask_turn',
    description: turn.plan || turn.error || '',
    resource: turn.sql || '',
  })), [completedTurns])

  const { searchQuery, setSearchQuery, filteredFindings } = useFindingsWorkbench(transcriptFindings, {
    csvPrefix: 'weissman-ask-transcript',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleHistory = useMemo(() => {
    if (!searchQuery.trim()) return history
    const ids = new Set(filteredFindings.map((f) => f.id))
    return history.filter((turn, _i) => {
      if (turn.pending) return true
      const idx = completedTurns.indexOf(turn)
      return idx >= 0 && ids.has(idx)
    })
  }, [history, completedTurns, filteredFindings, searchQuery])

  const ask = useCallback(async (q) => {
    const text = (q ?? question).trim()
    if (!text) return
    setQuestion('')
    setLoading(true)
    const placeholder = { q: text, pending: true, t: Date.now() }
    setHistory((h) => [...h, placeholder])
    try {
      const d = await apiFetch('/api/ask', {
        method: 'POST',
        body: { question: text },
      })
      const result = d?.result || {}
      setHistory((h) => {
        const next = [...h]
        const idx = next.findIndex((x) => x === placeholder)
        const turn = {
          q: text,
          ok: !result.error,
          error: result.error || null,
          guard: result.guard || null,
          plan: result.plan,
          sql: result.sql,
          rows: result.rows || [],
          row_count: result.row_count || 0,
          elapsed_ms: result.elapsed_ms,
          t: Date.now(),
        }
        if (idx >= 0) next[idx] = turn
        else next.push(turn)
        return next
      })
    } catch (e) {
      let msg
      if (e?.status) {
        const b = e.response ? await e.response.json().catch(() => ({})) : {}
        msg = formatApiErrorFromBody(b, e.status)
      } else {
        msg = e?.message || t('ask_weissman.network_error')
      }
      setHistory((h) => h.map((x) => x === placeholder ? {
        q: text, ok: false, error: msg, t: Date.now(),
      } : x))
    } finally {
      setLoading(false)
    }
  }, [question, t])

  const clearHistory = useCallback(() => {
    setHistory([])
    setQuestion('')
  }, [])

  const refreshSession = useCallback(() => {
    setQuestion('')
    if (transcriptRef.current) {
      transcriptRef.current.scrollTop = 0
    }
  }, [])

  useEffect(() => {
    if (transcriptRef.current) {
      transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight
    }
  }, [history])

  return (
    <main
      id="main-content"
      tabIndex={-1}
      className="min-h-[100dvh] text-[var(--text-secondary)] p-5 lg:p-6 flex flex-col outline-none"
      style={{ background: 'var(--shell-bg)' }}
    >
      <header className="mb-4 flex items-end justify-between gap-3 flex-wrap shrink-0">
        <div>
          <h1 className="text-xl font-bold tracking-tight">{t('ask_weissman.title')}</h1>
          <p className="text-xs text-[var(--text-tertiary)] mt-1">
            {t('ask_weissman.subtitle_full')}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <ShellScanActions
            onRefresh={refreshSession}
            onExport={() => exportTranscriptCsv(history)}
            exportDisabled={completedTurns.length === 0}
          />
          <Button variant="unstyled"
            type="button"
            onClick={clearHistory}
            disabled={history.length === 0}
            className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:border-rose-500/40 hover:text-rose-200 disabled:opacity-40"
          >
            <Trash2 className="w-3.5 h-3.5" />
            {t('pages.askWeissman.clear_history')}
          </Button>
          <Link to="/llm-ultra-guard" className="text-[11px] font-mono text-cyan-400/80 hover:text-cyan-200">
            {t('ask_weissman.open_ultra_guard')} →
          </Link>
          <Link to="/" className="text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] weissman-flip-x">
            {t('ask_weissman.back_cockpit')}
          </Link>
        </div>
      </header>

      <EvidenceNotice className="mb-3 shrink-0">{t('pages.askWeissman.evidence_notice')}</EvidenceNotice>

      {completedTurns.length > 0 && (
        <WeissmanListToolbar
          className="mb-3 shrink-0"
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          searchPlaceholder={t('pages.askWeissman.search_placeholder')}
          resultCount={searchQuery.trim() ? filteredFindings.length : completedTurns.length}
          totalCount={completedTurns.length}
        />
      )}

      <div className="flex flex-wrap gap-1.5 mb-3 shrink-0" role="group" aria-label={t('ask_weissman.sample_prompts')}>
        {sampleQuestions.map((s) => (
          <Button variant="unstyled"
            type="button"
            key={s}
            onClick={() => setQuestion(s)}
            className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:border-cyan-500/40 hover:text-cyan-200"
          >
            &ldquo;{s}&rdquo;
          </Button>
        ))}
      </div>

      <div
        ref={transcriptRef}
        className="flex-1 overflow-y-auto rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-4 space-y-4"
      >
        {visibleHistory.length === 0 && history.length > 0 ? (
          <div className="text-center text-[11px] font-mono text-[var(--text-muted)] py-12">
            {t('weissmanFindings.filtered_title')}
          </div>
        ) : visibleHistory.length === 0 ? (
          <div className="text-center text-[11px] font-mono text-[var(--text-muted)] py-12">
            {t('ask_weissman.empty_state')}
          </div>
        ) : null}
        {visibleHistory.map((turn, i) => (
          <div key={i}>
            <div className="flex items-start gap-2 mb-2">
              <span className="text-[10px] font-mono text-cyan-300 mt-0.5 weissman-flip-x">{t('ask_weissman.you_label')}</span>
              <p className="text-[13px] text-[var(--text-primary)] leading-snug flex-1">{turn.q}</p>
            </div>

            {turn.pending ? (
              <div className="ms-6 text-[11px] font-mono text-[var(--text-muted)]">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse me-2" />
                {t('ask_weissman.planning')}
              </div>
            ) : (
              <div className="ms-6 space-y-2">
                <div className="flex items-center gap-2">
                  <StatusBadge ok={turn.ok} error={turn.error} t={t} />
                  {turn.elapsed_ms != null && (
                    <span className="text-[10px] font-mono text-[var(--text-muted)] number-cell">
                      {turn.elapsed_ms}ms
                    </span>
                  )}
                  {turn.row_count != null && !turn.error && (
                    <span className="text-[10px] font-mono text-[var(--text-tertiary)]">
                      {t('ask_weissman.rows', { count: turn.row_count })}
                    </span>
                  )}
                  {turn.guard?.verdict && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                        turn.guard.verdict === 'block'
                          ? 'border-rose-500/40 bg-rose-500/15 text-rose-200'
                          : turn.guard.verdict === 'quarantine'
                            ? 'border-amber-500/40 bg-amber-500/15 text-amber-200'
                            : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                      }`}
                      title={turn.guard.fingerprint || ''}
                    >
                      {turn.guard.verdict === 'block'
                        ? t('ask_weissman.guard_block')
                        : turn.guard.verdict === 'quarantine'
                          ? t('ask_weissman.guard_quarantine')
                          : t('ask_weissman.guard_allow')}
                      {turn.guard.latency_us != null && (
                        <span className="ms-1 opacity-70">
                          {t('ask_weissman.guard_latency', { us: turn.guard.latency_us })}
                        </span>
                      )}
                    </span>
                  )}
                </div>

                {turn.error ? (
                  <p className="text-[12px] font-mono text-rose-300">{turn.error}</p>
                ) : (
                  <>
                    {turn.plan && (
                      <details className="rounded border border-[var(--border-default)] bg-[var(--bg-2)]" open>
                        <summary className="cursor-pointer text-[10px] font-mono text-violet-300/80 px-2 py-1 hover:text-violet-200">
                          {t('pages.askWeissman.plan_label')} ▾
                        </summary>
                        <pre className="text-[10px] font-mono text-[var(--text-secondary)] p-2 overflow-x-auto whitespace-pre-wrap">
                          {typeof turn.plan === 'string' ? turn.plan : JSON.stringify(turn.plan, null, 2)}
                        </pre>
                      </details>
                    )}

                    {turn.sql && (
                      <details className="rounded border border-[var(--border-default)] bg-[var(--bg-2)]">
                        <summary className="cursor-pointer text-[10px] font-mono text-cyan-300/70 px-2 py-1 hover:text-cyan-200">
                          {t('ask_weissman.compiled_sql')} ▾
                        </summary>
                        <pre className="text-[10px] font-mono text-emerald-300 p-2 overflow-x-auto whitespace-pre-wrap ltr-only">
                          {turn.sql}
                        </pre>
                      </details>
                    )}

                    {turn.rows && turn.rows.length > 0 ? (
                      <div className="rounded border border-[var(--border-default)] bg-[var(--table-surface)] overflow-x-auto custom-scroll">
                        <table className="min-w-full text-[11px] font-mono data-grid">
                          <thead>
                            <tr className="text-[var(--text-tertiary)]">
                              {Object.keys(turn.rows[0]).map((k) => (
                                <th key={k} scope="col" className="px-2 py-1.5 font-normal border-b border-[var(--border-default)]">
                                  {k}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {turn.rows.slice(0, 50).map((row, ri) => (
                              <tr key={ri} className="text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)]">
                                {Object.values(row).map((v, ci) => (
                                  <td key={ci} className="px-2 py-1 border-b border-white/[0.04] whitespace-nowrap number-cell">
                                    {fmtCell(v)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {turn.rows.length > 50 && (
                          <p className="text-center text-[10px] font-mono text-[var(--text-muted)] py-1.5 border-t border-[var(--border-default)]">
                            {t('ask_weissman.showing_rows', { total: turn.row_count })}
                          </p>
                        )}
                      </div>
                    ) : (
                      <p className="text-[11px] font-mono text-[var(--text-muted)]">
                        {t('ask_weissman.no_rows')}
                      </p>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      <form
        className="mt-3 flex gap-2 shrink-0"
        onSubmit={(e) => { e.preventDefault(); ask() }}
      >
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder={t('ask_weissman.placeholder')}
          aria-label={t('ask_weissman.placeholder')}
          className="flex-1 bg-[var(--bg-2)] border border-[var(--border-strong)] rounded-lg px-3 py-2 text-[13px] text-[var(--text-primary)] focus:outline-none focus:border-cyan-500/40"
          // eslint-disable-next-line jsx-a11y/no-autofocus -- intentional: focus the primary question input on this dedicated Q&A page
          autoFocus
        />
        <Button variant="unstyled"
          type="submit"
          disabled={loading || !question.trim()}
          className="px-4 py-2 rounded-lg text-[12px] font-mono uppercase tracking-widest border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25 disabled:opacity-40 weissman-flip-x"
        >
          {loading ? t('ask_weissman.asking') : t('ask_weissman.ask_button')}
        </Button>
      </form>
    </main>
  )
}
