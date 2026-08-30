import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import Button from '../components/ui/Button'
import { apiFetch } from '../utils/apiFetch'
import { openSseStream } from '../lib/sseStream'

const SHIFTS = ['red', 'blue', 'cloud', 'grc', 'hunter']
const NS = 'pages.sovereignTheater'

function phaseTone(phase) {
  if (phase === 'failed') return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
  if (phase === 'finding') return 'text-amber-200 border-amber-500/40 bg-amber-500/10'
  if (phase === 'entered' || phase === 'probe') return 'text-cyan-200 border-cyan-500/40 bg-cyan-500/10'
  if (phase === 'retry') return 'text-orange-200 border-orange-500/40 bg-orange-500/10'
  return 'text-emerald-200 border-emerald-500/30 bg-emerald-500/10'
}

function thoughtTone(kind) {
  if (kind === 'enter_engine') return 'border-cyan-400/50 bg-cyan-500/10'
  if (kind === 'wait_roe') return 'border-amber-400/50 bg-amber-500/10'
  if (kind === 'correlate') return 'border-violet-400/50 bg-violet-500/10'
  if (kind === 'decide') return 'border-emerald-400/50 bg-emerald-500/10'
  return 'border-[var(--border-default)] bg-[var(--row-hover-bg)]'
}

export default function SovereignTheater() {
  const { t } = useTranslation()
  const [sessionId, setSessionId] = useState('')
  const [messages, setMessages] = useState([])
  const [windows, setWindows] = useState([])
  const [logs, setLogs] = useState([])
  const [knowledge, setKnowledge] = useState(null)
  const [question, setQuestion] = useState('')
  const [shift, setShift] = useState('red')
  const [clientId, setClientId] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')
  const [sectionSearch, setSectionSearch] = useState('')
  const [exporting, setExporting] = useState(false)
  const sinceRef = useRef(0)
  const chatEndRef = useRef(null)

  const loadSession = useCallback(async () => {
    const d = await apiFetch('/api/sovereign/operator/session')
    if (d?.session_id) setSessionId(d.session_id)
    setMessages(Array.isArray(d?.messages) ? d.messages : [])
  }, [])

  const loadWindows = useCallback(async () => {
    const d = await apiFetch('/api/sovereign/operator/windows')
    setWindows(Array.isArray(d?.windows) ? d.windows : [])
  }, [])

  const loadLogs = useCallback(async () => {
    const d = await apiFetch('/api/sovereign/operator/logs?limit=80')
    const events = Array.isArray(d?.events) ? d.events : []
    setLogs(events)
    const maxId = events.reduce((m, e) => Math.max(m, Number(e.id) || 0), sinceRef.current)
    sinceRef.current = maxId
  }, [])

  const loadKnowledge = useCallback(async () => {
    const d = await apiFetch('/api/sovereign/operator/knowledge')
    setKnowledge(d?.knowledge || null)
  }, [])

  const refresh = useCallback(async () => {
    setError('')
    try {
      await Promise.all([loadSession(), loadWindows(), loadLogs(), loadKnowledge()])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    }
  }, [loadSession, loadWindows, loadLogs, loadKnowledge, t])

  useEffect(() => {
    refresh()
  }, [refresh])

  useEffect(() => {
    const es = openSseStream('/api/sovereign/operator/stream?since=0', {
      getReconnectUrl: () => `/api/sovereign/operator/stream?since=${sinceRef.current}`,
    })
    const onLog = (ev) => {
      try {
        const row = JSON.parse(ev.data)
        const id = Number(row.id) || 0
        if (id) sinceRef.current = Math.max(sinceRef.current, id)
        setLogs((prev) => [...prev.slice(-200), row])
        loadWindows()
      } catch {
        /* ignore malformed frames */
      }
    }
    es.addEventListener('engine_log', onLog)
    return () => {
      es.close?.()
    }
  }, [loadWindows])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView?.({ behavior: 'smooth' })
  }, [messages])

  const handleExport = useCallback(async () => {
    setExporting(true)
    try {
      const bundle = {
        exported_at: new Date().toISOString(),
        session_id: sessionId,
        messages,
        windows,
        logs,
        knowledge,
      }
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `weissman-sovereign-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setExporting(false)
    }
  }, [sessionId, messages, windows, logs, knowledge])

  const send = useCallback(async () => {
    const q = question.trim()
    if (!q || sending) return
    setSending(true)
    setError('')
    try {
      const d = await apiFetch('/api/sovereign/operator/chat', {
        method: 'POST',
        body: { question: q, session_id: sessionId || undefined, shift },
      })
      if (d?.session_id) setSessionId(d.session_id)
      setQuestion('')
      await loadSession()
      await loadWindows()
    } catch (e) {
      setError(e.message || t(`${NS}.chat_failed`))
    } finally {
      setSending(false)
    }
  }, [question, sending, sessionId, shift, loadSession, loadWindows, t])

  const runRace = useCallback(async () => {
    const cid = Number(clientId)
    if (!Number.isFinite(cid) || cid <= 0) {
      setError(t(`${NS}.client_required`))
      return
    }
    setSending(true)
    setError('')
    try {
      await apiFetch('/api/sovereign/operator/race', {
        method: 'POST',
        body: {
          confirmation: 'AUTHORIZED',
          client_id: cid,
          shift,
        },
      })
      await Promise.all([loadSession(), loadWindows(), loadLogs()])
    } catch (e) {
      setError(e.message || t(`${NS}.race_failed`))
    } finally {
      setSending(false)
    }
  }, [clientId, shift, loadSession, loadWindows, loadLogs, t])

  const runTune = useCallback(async () => {
    setSending(true)
    setError('')
    try {
      await apiFetch('/api/sovereign/operator/tune', { method: 'POST', body: {} })
      await loadWindows()
    } catch (e) {
      setError(e.message || t(`${NS}.tune_failed`))
    } finally {
      setSending(false)
    }
  }, [loadWindows, t])

  const q = sectionSearch.trim().toLowerCase()
  const thoughts = useMemo(
    () =>
      messages.filter((m) => {
        if (m.role !== 'thought') return false
        if (!q) return true
        return `${m.thought_kind || ''} ${m.content || ''}`.toLowerCase().includes(q)
      }),
    [messages, q],
  )
  const chatTurns = useMemo(
    () =>
      messages.filter((m) => {
        if (!['user', 'assistant', 'tool'].includes(m.role)) return false
        if (!q) return true
        return `${m.role} ${m.content || ''} ${m.tool_name || ''}`.toLowerCase().includes(q)
      }),
    [messages, q],
  )
  const openWindows = useMemo(
    () =>
      windows.filter((w) => {
        if (q && !`${w.engine_id || ''} ${w.target || ''} ${w.phase || ''}`.toLowerCase().includes(q)) return false
        return w.open
      }),
    [windows, q],
  )
  const filteredLogs = useMemo(
    () =>
      logs.filter((l) => {
        if (!q) return true
        return `${l.engine_id || ''} ${l.phase || ''} ${l.detail || ''}`.toLowerCase().includes(q)
      }),
    [logs, q],
  )

  return (
    <div className="min-h-screen text-[var(--text-secondary)]" style={{ background: 'var(--shell-bg)' }}>
      <header className="border-b border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-[1600px] mx-auto px-4 py-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">{t(`${NS}.title`)}</h1>
            <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mt-1">
              {t(`${NS}.subtitle`)}
            </p>
          </div>
          <ShellScanActions
            onRefresh={refresh}
            onExport={handleExport}
            exportDisabled={exporting}
            exportLabel={t(`${NS}.export_json`)}
          />
        </div>
      </header>

      <div className="max-w-[1600px] mx-auto px-4 py-4 space-y-4">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
        <WeissmanListToolbar
          searchQuery={sectionSearch}
          onSearchChange={setSectionSearch}
          searchPlaceholder={t(`${NS}.search_placeholder`)}
        />
        {error ? (
          <div className="text-sm text-rose-300 border border-rose-500/30 rounded-lg px-3 py-2">{error}</div>
        ) : null}

        <div className="flex flex-wrap gap-2 items-end">
          <label className="text-[11px] font-mono text-[var(--text-muted)]">
            {t(`${NS}.shift`)}
            <select
              className="ml-2 bg-[var(--table-surface)] border border-[var(--border-default)] rounded px-2 py-1 text-xs"
              value={shift}
              onChange={(e) => setShift(e.target.value)}
            >
              {SHIFTS.map((s) => (
                <option key={s} value={s}>
                  {t(`${NS}.shift_${s}`)}
                </option>
              ))}
            </select>
          </label>
          <label className="text-[11px] font-mono text-[var(--text-muted)]">
            {t(`${NS}.client_id`)}
            <input
              type="number"
              min="1"
              className="ml-2 bg-[var(--table-surface)] border border-[var(--border-default)] rounded px-2 py-1 text-xs w-28"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
            />
          </label>
          <Button type="button" variant="primary" disabled={sending} onClick={runRace}>
            {t(`${NS}.authorize_race`)}
          </Button>
          <Button type="button" variant="secondary" disabled={sending} onClick={runTune}>
            {t(`${NS}.tune_now`)}
          </Button>
          {knowledge?.production_engine_count != null ? (
            <span className="text-[10px] font-mono text-[var(--text-muted)]">
              {t(`${NS}.engine_count`, { n: knowledge.production_engine_count })}
            </span>
          ) : null}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <section className="xl:col-span-1 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] flex flex-col min-h-[28rem]">
            <h2 className="px-3 py-2 text-[11px] font-mono uppercase tracking-widest text-cyan-300 border-b border-[var(--border-default)]">
              {t(`${NS}.chat`)}
            </h2>
            <div className="flex-1 overflow-auto p-3 space-y-2 text-sm">
              {chatTurns.map((m) => (
                <div
                  key={m.id || `${m.role}-${m.ts}`}
                  className={`rounded-lg px-3 py-2 border ${
                    m.role === 'user'
                      ? 'border-cyan-500/20 bg-cyan-500/5 ml-6'
                      : m.role === 'tool'
                        ? 'border-amber-500/20 bg-amber-500/5 font-mono text-[11px]'
                        : 'border-[var(--border-default)] mr-6'
                  }`}
                >
                  <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-1">
                    {m.role}
                    {m.tool_name ? ` · ${m.tool_name}` : ''}
                  </div>
                  <div className="whitespace-pre-wrap">{m.content}</div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
            <form
              className="p-3 border-t border-[var(--border-default)] flex gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                send()
              }}
            >
              <input
                className="flex-1 bg-[var(--shell-bg)] border border-[var(--border-default)] rounded px-3 py-2 text-sm"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder={t(`${NS}.placeholder`)}
                disabled={sending}
              />
              <Button type="submit" variant="primary" disabled={sending}>
                {sending ? t(`${NS}.sending`) : t(`${NS}.send`)}
              </Button>
            </form>
          </section>

          <section className="xl:col-span-1 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] min-h-[28rem]">
            <h2 className="px-3 py-2 text-[11px] font-mono uppercase tracking-widest text-violet-300 border-b border-[var(--border-default)]">
              {t(`${NS}.thoughts`)}
            </h2>
            <div className="p-3 space-y-2 overflow-auto max-h-[36rem]">
              {thoughts.length === 0 ? (
                <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.no_thoughts`)}</p>
              ) : (
                thoughts.map((m) => (
                  <div
                    key={m.id || m.ts}
                    className={`rounded-lg border px-3 py-2 text-sm ${thoughtTone(m.thought_kind)}`}
                  >
                    <div className="text-[10px] font-mono uppercase tracking-widest mb-1">{m.thought_kind}</div>
                    <div className="whitespace-pre-wrap">{m.content}</div>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="xl:col-span-1 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] min-h-[28rem]">
            <h2 className="px-3 py-2 text-[11px] font-mono uppercase tracking-widest text-amber-300 border-b border-[var(--border-default)]">
              {t(`${NS}.windows`)}
            </h2>
            <div className="p-3 space-y-2 overflow-auto max-h-[36rem]">
              {openWindows.length === 0 ? (
                <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.no_windows`)}</p>
              ) : (
                openWindows.map((w) => (
                  <div
                    key={`${w.engine_id}-${w.job_id || w.id}`}
                    className={`rounded-lg border px-3 py-2 font-mono text-[11px] ${phaseTone(w.phase)}`}
                  >
                    <div className="flex justify-between gap-2">
                      <span className="font-semibold">{w.engine_id}</span>
                      <span className="uppercase">{w.phase}</span>
                    </div>
                    <div className="opacity-80 truncate">{w.target}</div>
                    {w.detail ? <div className="opacity-70 mt-1">{w.detail}</div> : null}
                  </div>
                ))
              )}
            </div>
          </section>
        </div>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)]">
          <h2 className="px-3 py-2 text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] border-b border-[var(--border-default)]">
            {t(`${NS}.terminal`)}
          </h2>
          <pre className="p-3 text-[11px] font-mono overflow-auto max-h-64 leading-relaxed text-cyan-100/80">
            {filteredLogs.length === 0
              ? t(`${NS}.no_logs`)
              : filteredLogs
                  .slice(-80)
                  .map((l) => `[${l.ts || ''}] ${l.phase} ${l.engine_id} ${l.target || ''} ${l.detail || ''}`)
                  .join('\n')}
          </pre>
        </section>
      </div>
    </div>
  )
}
