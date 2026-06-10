import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'
import { formatApiErrorFromBody } from '../lib/apiError'

/**
 * Ask Weissman — chat-style natural-language interface that compiles questions
 * to safe, parameterised SQL and runs them against a read-only Postgres role.
 *
 *   * Hits POST /api/ask
 *   * Shows the compiled SQL (transparency!) + the rows in a real table
 *   * History is local (per session) — the audit trail lives server-side in
 *     `nl_query_audit`
 *
 * Hard guarantees the user can see:
 *   * Every query starts with `tenant_id = $1` (server-injected)
 *   * Only SELECTs are executed (read-only role enforces this)
 *   * Statement timeout = 15 s; result rows capped at 200
 */

const SAMPLE_QUESTIONS = [
  'show me critical KEV findings discovered in the last 7 days',
  'top 20 vulnerabilities by EPSS score',
  'list assets flagged as crown jewels with business value over 100000',
  'all UEBA anomalies with z-score above 5 in the last day',
  'open findings on internet-exposed nodes',
]

function fmtCell(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? '✓' : '✗'
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3)
  return String(v)
}

function StatusBadge({ ok, error }) {
  if (error) {
    return (
      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/15 text-rose-200">
        error
      </span>
    )
  }
  if (ok) {
    return (
      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-200">
        ok
      </span>
    )
  }
  return (
    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-white/15 bg-white/10 text-white/60">
      pending
    </span>
  )
}

export default function AskWeissman() {
  const [question, setQuestion] = useState('')
  const [history, setHistory] = useState([])  // [{ q, plan, sql, rows, error, elapsed_ms, t }]
  const [loading, setLoading] = useState(false)
  const transcriptRef = useRef(null)

  const ask = useCallback(async (q) => {
    const text = (q ?? question).trim()
    if (!text) return
    setQuestion('')
    setLoading(true)
    // Optimistic placeholder for the in-flight turn.
    const placeholder = { q: text, pending: true, t: Date.now() }
    setHistory((h) => [...h, placeholder])
    try {
      const r = await apiFetch('/api/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: text }),
      })
      const d = await r.json().catch(() => ({}))
      const result = d?.result || {}
      setHistory((h) => {
        const next = [...h]
        const idx = next.findIndex((x) => x === placeholder)
        const turn = {
          q: text,
          ok: !result.error,
          error: result.error || (r.ok ? null : formatApiErrorFromBody(d, r.status)),
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
      setHistory((h) => h.map((x) => x === placeholder ? {
        q: text, ok: false, error: e?.message || 'network error', t: Date.now(),
      } : x))
    } finally {
      setLoading(false)
    }
  }, [question])

  useEffect(() => {
    if (transcriptRef.current) {
      transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight
    }
  }, [history])

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-5 lg:p-6 flex flex-col"
      style={{
        background:
          'radial-gradient(ellipse 120% 80% at 50% 0%, #111827 0%, #09090b 50%, #030712 100%)',
      }}
    >
      <header className="mb-4 flex items-end justify-between gap-3 flex-wrap shrink-0">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Ask Weissman</h1>
          <p className="text-xs text-white/55 mt-1">
            Natural-language queries compiled to safe, parameterised SQL. Read-only role,
            tenant-scoped, statement timeout 15&nbsp;s. Every question is audited.
          </p>
        </div>
        <Link to="/" className="text-[11px] font-mono text-white/45 hover:text-white/80">
          ← Cockpit
        </Link>
      </header>

      {/* Sample chips — copied to the input when clicked */}
      <div className="flex flex-wrap gap-1.5 mb-3 shrink-0">
        {SAMPLE_QUESTIONS.map((s) => (
          <button
            type="button"
            key={s}
            onClick={() => setQuestion(s)}
            className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-white/60 hover:border-cyan-500/40 hover:text-cyan-200"
          >
            “{s}”
          </button>
        ))}
      </div>

      {/* Transcript */}
      <div
        ref={transcriptRef}
        className="flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-4 space-y-4"
      >
        {history.length === 0 && (
          <div className="text-center text-[11px] font-mono text-white/35 py-12">
            Ask a question above to get started. Try one of the sample prompts.
          </div>
        )}
        {history.map((t, i) => (
          <div key={i}>
            <div className="flex items-start gap-2 mb-2">
              <span className="text-[10px] font-mono text-cyan-300 mt-0.5">YOU →</span>
              <p className="text-[13px] text-white/90 leading-snug flex-1">{t.q}</p>
            </div>

            {t.pending ? (
              <div className="ms-6 text-[11px] font-mono text-white/45">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse mr-2" />
                planning + running query…
              </div>
            ) : (
              <div className="ms-6 space-y-2">
                <div className="flex items-center gap-2">
                  <StatusBadge ok={t.ok} error={t.error} />
                  {t.elapsed_ms != null && (
                    <span className="text-[10px] font-mono text-white/40">
                      {t.elapsed_ms}ms
                    </span>
                  )}
                  {t.row_count != null && !t.error && (
                    <span className="text-[10px] font-mono text-white/55">
                      {t.row_count} rows
                    </span>
                  )}
                </div>

                {t.error ? (
                  <p className="text-[12px] font-mono text-rose-300">{t.error}</p>
                ) : (
                  <>
                    {/* Compiled SQL transparency */}
                    {t.sql && (
                      <details className="rounded border border-white/10 bg-black/40">
                        <summary className="cursor-pointer text-[10px] font-mono text-cyan-300/70 px-2 py-1 hover:text-cyan-200">
                          Compiled SQL ▾
                        </summary>
                        <pre className="text-[10px] font-mono text-emerald-300 p-2 overflow-x-auto whitespace-pre-wrap">
                          {t.sql}
                        </pre>
                      </details>
                    )}

                    {/* Rows */}
                    {t.rows && t.rows.length > 0 ? (
                      <div className="rounded border border-white/10 bg-black/30 overflow-x-auto custom-scroll">
                        <table className="min-w-full text-[11px] font-mono">
                          <thead>
                            <tr className="text-white/50">
                              {Object.keys(t.rows[0]).map((k) => (
                                <th key={k} className="px-2 py-1.5 text-left font-normal border-b border-white/10">
                                  {k}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {t.rows.slice(0, 50).map((row, ri) => (
                              <tr key={ri} className="text-white/80 hover:bg-white/[0.03]">
                                {Object.values(row).map((v, ci) => (
                                  <td key={ci} className="px-2 py-1 border-b border-white/[0.04] whitespace-nowrap">
                                    {fmtCell(v)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {t.rows.length > 50 && (
                          <p className="text-center text-[10px] font-mono text-white/35 py-1.5 border-t border-white/10">
                            showing first 50 of {t.row_count} rows
                          </p>
                        )}
                      </div>
                    ) : (
                      <p className="text-[11px] font-mono text-white/45">
                        (no rows)
                      </p>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Input bar */}
      <form
        className="mt-3 flex gap-2 shrink-0"
        onSubmit={(e) => { e.preventDefault(); ask() }}
      >
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask anything about your data — e.g. ‘top 5 KEV findings on prod assets’"
          className="flex-1 bg-black/40 border border-white/15 rounded-lg px-3 py-2 text-[13px] text-white/90 focus:outline-none focus:border-cyan-500/40"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading || !question.trim()}
          className="px-4 py-2 rounded-lg text-[12px] font-mono uppercase tracking-widest border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25 disabled:opacity-40"
        >
          {loading ? 'Asking…' : 'Ask →'}
        </button>
      </form>
    </div>
  )
}
