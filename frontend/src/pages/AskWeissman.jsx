import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ArrowUp,
  ChevronDown,
  Copy,
  Check,
  Sparkles,
  Shield,
  Database,
} from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import { formatApiErrorFromBody } from '../lib/apiError'

const SAMPLE_QUESTIONS = [
  'show me critical KEV findings discovered in the last 7 days',
  'top 20 vulnerabilities by EPSS score',
  'list assets flagged as crown jewels with business value over 100000',
  'all UEBA anomalies with z-score above 5 in the last day',
  'open findings on internet-exposed nodes',
]

const SQL_KEYWORDS = new Set([
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'JOIN', 'LEFT', 'RIGHT',
  'INNER', 'OUTER', 'ON', 'AS', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT',
  'OFFSET', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN', 'CASE', 'WHEN',
  'THEN', 'ELSE', 'END', 'IS', 'NULL', 'LIKE', 'ILIKE', 'BETWEEN', 'EXISTS',
  'WITH', 'UNION', 'ALL', 'ASC', 'DESC', 'TRUE', 'FALSE', 'CAST', 'COALESCE',
])

function fmtCell(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'boolean') return v ? '✓' : '✗'
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3)
  return String(v)
}

function highlightSql(sql) {
  if (!sql) return null
  const tokens = sql.split(/(\s+|[(),;=<>!]+|\$?\d+)/g).filter(Boolean)
  return tokens.map((tok, i) => {
    const upper = tok.toUpperCase()
    if (SQL_KEYWORDS.has(upper)) {
      return <span key={i} className="sql-kw">{tok}</span>
    }
    if (/^\$?\d+$/.test(tok)) {
      return <span key={i} className="sql-num">{tok}</span>
    }
    if (tok.startsWith("'") || tok.startsWith('"')) {
      return <span key={i} className="sql-str">{tok}</span>
    }
    if (/^[(),;=<>!]+$/.test(tok)) {
      return <span key={i} className="sql-punct">{tok}</span>
    }
    return <span key={i}>{tok}</span>
  })
}

function TypingIndicator({ label }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500/20 to-violet-500/20 ring-1 ring-cyan-400/30">
        <Sparkles className="h-4 w-4 text-cyan-300" strokeWidth={1.75} />
      </div>
      <div className="flex items-center gap-1.5 rounded-2xl rounded-tl-sm bg-zinc-800/80 px-4 py-3 ring-1 ring-white/[0.06]">
        <span className="typing-dot" />
        <span className="typing-dot animation-delay-150" />
        <span className="typing-dot animation-delay-300" />
        <span className="sr-only">{label}</span>
      </div>
    </div>
  )
}

function SqlPanel({ sql, label, copyLabel, copiedLabel }) {
  const [open, setOpen] = useState(true)
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(sql)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (_) { /* ignore */ }
  }

  return (
    <div className="overflow-hidden rounded-xl ring-1 ring-white/[0.08] bg-[#0c0c0e]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-white/[0.03]"
      >
        <span className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-cyan-300/80">
          <Database className="h-3.5 w-3.5" strokeWidth={1.75} />
          {label}
        </span>
        <span className="flex items-center gap-2">
          <span
            role="button"
            tabIndex={0}
            onClick={(e) => { e.stopPropagation(); copy() }}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); copy() } }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-medium text-white/50 transition-colors hover:bg-white/[0.06] hover:text-white/80"
          >
            {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            {copied ? copiedLabel : copyLabel}
          </span>
          <ChevronDown className={`h-4 w-4 text-white/40 transition-transform ${open ? 'rotate-180' : ''}`} />
        </span>
      </button>
      {open && (
        <div className="sql-editor border-t border-white/[0.06]">
          <div className="sql-gutter">
            {sql.split('\n').map((_, i) => (
              <span key={i}>{i + 1}</span>
            ))}
          </div>
          <pre className="sql-code custom-scroll">
            <code>{highlightSql(sql)}</code>
          </pre>
        </div>
      )}
    </div>
  )
}

function ResultsGrid({ rows, truncatedLabel }) {
  if (!rows?.length) return null
  const cols = Object.keys(rows[0])
  return (
    <div className="overflow-hidden rounded-xl ring-1 ring-white/[0.08]">
      <div className="overflow-x-auto custom-scroll">
        <table className="premium-grid min-w-full">
          <thead>
            <tr>
              {cols.map((k) => (
                <th key={k}>{k}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 50).map((row, ri) => (
              <tr key={ri}>
                {cols.map((k) => (
                  <td key={k}>{fmtCell(row[k])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > 50 && (
        <p className="border-t border-white/[0.06] bg-zinc-900/60 px-4 py-2 text-center text-[11px] text-white/35">
          {truncatedLabel}
        </p>
      )}
    </div>
  )
}

function AssistantTurn({ turn, t }) {
  return (
    <div className="flex items-start gap-3 max-w-[92%]">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500/25 to-violet-600/25 ring-1 ring-cyan-400/25">
        <Sparkles className="h-4 w-4 text-cyan-200" strokeWidth={1.75} />
      </div>
      <div className="min-w-0 flex-1 space-y-3">
        <div className="rounded-2xl rounded-tl-sm bg-zinc-800/70 px-4 py-3 ring-1 ring-white/[0.06] backdrop-blur-sm">
          {turn.error ? (
            <p className="text-[13px] leading-relaxed text-rose-300">{turn.error}</p>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-300 ring-1 ring-emerald-500/30">
                {t('common.success')}
              </span>
              {turn.elapsed_ms != null && (
                <span className="text-[11px] text-white/40">{t('ask_weissman.elapsed_ms', { ms: turn.elapsed_ms })}</span>
              )}
              {turn.row_count != null && (
                <span className="text-[11px] text-white/50">{t('ask_weissman.rows_count', { count: turn.row_count })}</span>
              )}
            </div>
          )}
        </div>

        {!turn.error && turn.sql && (
          <SqlPanel
            sql={turn.sql}
            label={t('ask_weissman.compiled_sql')}
            copyLabel={t('common.copy')}
            copiedLabel={t('common.copied')}
          />
        )}

        {!turn.error && (
          <div>
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-white/35">
              {t('ask_weissman.results')}
            </p>
            <ResultsGrid
              rows={turn.rows}
              truncatedLabel={t('ask_weissman.rows_truncated', { count: turn.row_count })}
            />
            {(!turn.rows || turn.rows.length === 0) && (
              <p className="mt-2 text-[12px] text-white/40">{t('ask_weissman.no_rows')}</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function AskWeissman() {
  const { t } = useTranslation()
  const [question, setQuestion] = useState('')
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const transcriptRef = useRef(null)
  const inputRef = useRef(null)

  const ask = useCallback(async (q) => {
    const text = (q ?? question).trim()
    if (!text) return
    setQuestion('')
    setLoading(true)
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
        q: text, ok: false, error: e?.message || t('ask_weissman.network_error'), t: Date.now(),
      } : x))
    } finally {
      setLoading(false)
    }
  }, [question, t])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      if (!loading && question.trim()) ask()
    }
  }

  useEffect(() => {
    if (transcriptRef.current) {
      transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight
    }
  }, [history, loading])

  return (
    <div className="ask-weissman-root flex min-h-[100dvh] flex-col text-slate-100">
      {/* Header */}
      <header className="shrink-0 border-b border-white/[0.06] bg-[#09090b]/80 px-5 py-4 backdrop-blur-xl lg:px-8">
        <div className="mx-auto flex max-w-4xl items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 via-violet-500/15 to-amber-500/10 ring-1 ring-cyan-400/20">
              <Sparkles className="h-5 w-5 text-cyan-300" strokeWidth={1.5} />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-white">{t('ask_weissman.title')}</h1>
              <p className="text-[12px] text-white/45">{t('ask_weissman.subtitle')}</p>
            </div>
          </div>
          <Link
            to="/"
            className="text-[12px] font-medium text-white/40 transition-colors hover:text-white/70"
          >
            ← {t('nav.cockpit')}
          </Link>
        </div>
        <div className="mx-auto mt-3 flex max-w-4xl items-center gap-2 text-[11px] text-white/35">
          <Shield className="h-3.5 w-3.5 text-emerald-400/70" strokeWidth={1.75} />
          <span>{t('ask_weissman.audit_note')}</span>
          <span className="text-white/15">·</span>
          <span className="text-cyan-400/60">{t('ask_weissman.transparency')}</span>
        </div>
      </header>

      {/* Transcript */}
      <div ref={transcriptRef} className="flex-1 overflow-y-auto custom-scroll">
        <div className="mx-auto max-w-4xl space-y-8 px-5 py-8 lg:px-8">
          {history.length === 0 && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex flex-col items-center justify-center py-16 text-center"
            >
              <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/15 to-violet-600/15 ring-1 ring-white/[0.08]">
                <Sparkles className="h-8 w-8 text-cyan-300/80" strokeWidth={1.25} />
              </div>
              <p className="max-w-md text-[15px] leading-relaxed text-white/50">
                {t('ask_weissman.empty_state')}
              </p>
            </motion.div>
          )}

          <AnimatePresence initial={false}>
            {history.map((turn, i) => (
              <motion.div
                key={turn.t ?? i}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
                className="space-y-4"
              >
                {/* User bubble */}
                <div className="flex justify-end">
                  <div className="max-w-[85%] rounded-2xl rounded-tr-sm bg-gradient-to-br from-cyan-600/25 to-violet-600/20 px-4 py-3 ring-1 ring-cyan-400/20 backdrop-blur-sm">
                    <p className="text-[14px] leading-relaxed text-white/95">{turn.q}</p>
                  </div>
                </div>

                {/* Assistant */}
                {turn.pending ? (
                  <TypingIndicator label={t('ask_weissman.planning')} />
                ) : (
                  <AssistantTurn turn={turn} t={t} />
                )}
              </motion.div>
            ))}
          </AnimatePresence>

          {loading && history.length > 0 && !history[history.length - 1]?.pending && (
            <TypingIndicator label={t('ask_weissman.planning')} />
          )}
        </div>
      </div>

      {/* Input dock */}
      <div className="shrink-0 border-t border-white/[0.06] bg-[#09090b]/90 px-5 py-4 backdrop-blur-xl lg:px-8">
        <div className="mx-auto max-w-4xl">
          <div className="relative rounded-2xl bg-zinc-900/80 ring-1 ring-white/[0.08] transition-shadow focus-within:ring-cyan-500/30 focus-within:shadow-[0_0_40px_-12px_rgba(34,211,238,0.15)]">
            <textarea
              ref={inputRef}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t('ask_weissman.placeholder')}
              rows={1}
              className="block w-full resize-none bg-transparent px-4 py-3.5 pr-14 text-[14px] leading-relaxed text-white/90 placeholder:text-white/30 focus:outline-none"
              style={{ minHeight: '52px', maxHeight: '160px' }}
              onInput={(e) => {
                e.target.style.height = 'auto'
                e.target.style.height = `${Math.min(e.target.scrollHeight, 160)}px`
              }}
              autoFocus
            />
            <button
              type="button"
              onClick={() => ask()}
              disabled={loading || !question.trim()}
              className="absolute bottom-2.5 end-2.5 flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-cyan-600 text-white shadow-lg shadow-cyan-500/20 transition-all hover:from-cyan-400 hover:to-cyan-500 disabled:opacity-30 disabled:shadow-none"
              aria-label={t('ask_weissman.ask_button')}
            >
              <ArrowUp className="h-4 w-4" strokeWidth={2.5} />
            </button>
          </div>

          <p className="mt-3 text-[10px] font-medium uppercase tracking-wider text-white/30">
            {t('ask_weissman.sample_prompts')}
          </p>
          <div className="mt-2 flex flex-wrap gap-2 pb-1">
            {SAMPLE_QUESTIONS.map((s) => (
              <button
                type="button"
                key={s}
                onClick={() => {
                  setQuestion(s)
                  inputRef.current?.focus()
                }}
                className="rounded-full bg-white/[0.04] px-3.5 py-1.5 text-[12px] text-white/55 ring-1 ring-white/[0.08] transition-all hover:bg-cyan-500/10 hover:text-cyan-200 hover:ring-cyan-400/25"
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        .ask-weissman-root {
          background:
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(34, 211, 238, 0.08), transparent),
            radial-gradient(ellipse 60% 40% at 100% 0%, rgba(139, 92, 246, 0.06), transparent),
            linear-gradient(180deg, #0a0a0c 0%, #09090b 40%, #030712 100%);
        }
        .typing-dot {
          display: inline-block;
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: rgba(255,255,255,0.45);
          animation: typing-bounce 1.2s ease-in-out infinite;
        }
        .animation-delay-150 { animation-delay: 0.15s; }
        .animation-delay-300 { animation-delay: 0.3s; }
        @keyframes typing-bounce {
          0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
          30% { transform: translateY(-4px); opacity: 1; }
        }
        .sql-editor {
          display: grid;
          grid-template-columns: auto 1fr;
          font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace;
          font-size: 12px;
          line-height: 1.6;
          max-height: 280px;
          overflow: auto;
        }
        .sql-gutter {
          display: flex;
          flex-direction: column;
          padding: 12px 0;
          background: rgba(0,0,0,0.35);
          border-right: 1px solid rgba(255,255,255,0.06);
          user-select: none;
        }
        .sql-gutter span {
          display: block;
          padding: 0 12px;
          text-align: right;
          color: rgba(255,255,255,0.2);
          min-width: 2.5rem;
        }
        .sql-code {
          padding: 12px 16px;
          margin: 0;
          color: #a7f3d0;
          white-space: pre-wrap;
          word-break: break-word;
        }
        .sql-kw { color: #67e8f9; font-weight: 500; }
        .sql-num { color: #fcd34d; }
        .sql-str { color: #fca5a5; }
        .sql-punct { color: rgba(255,255,255,0.35); }
        .premium-grid thead tr {
          background: linear-gradient(180deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%);
        }
        .premium-grid th {
          padding: 10px 14px;
          text-align: left;
          font-size: 10px;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: rgba(255,255,255,0.45);
          border-bottom: 1px solid rgba(255,255,255,0.08);
          white-space: nowrap;
        }
        .premium-grid td {
          padding: 10px 14px;
          font-size: 12px;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          color: rgba(255,255,255,0.82);
          border-bottom: 1px solid rgba(255,255,255,0.04);
          white-space: nowrap;
        }
        .premium-grid tbody tr {
          transition: background 0.15s;
        }
        .premium-grid tbody tr:hover {
          background: rgba(34, 211, 238, 0.04);
        }
        .premium-grid tbody tr:nth-child(even) {
          background: rgba(255,255,255,0.015);
        }
        .premium-grid tbody tr:nth-child(even):hover {
          background: rgba(34, 211, 238, 0.04);
        }
        .sr-only {
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip: rect(0,0,0,0);
          border: 0;
        }
      `}</style>
    </div>
  )
}
