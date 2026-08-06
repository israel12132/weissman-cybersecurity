/**
 * Module 6: AI Red Teaming Arena — split-screen attacker vs defender, live judge status.
 * Left: Our LLM (Attacker) payloads. Right: Target LLM (Defender) responses. Center: JAILBREAK SUCCESS / SECURE.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'
import StandaloneLabShell from './ui/StandaloneLabShell'
import Button from './ui/Button'

const NS = 'components.tools.aiRedteamArena'

const WS_BASE = () => {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}`
}

export default function AIRedteamArena() {
  const { t } = useTranslation()
  const { clientId } = useParams()
  const [target, setTarget] = useState('')
  const [aiEndpoint, setAiEndpoint] = useState('')
  const [client, setClient] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [attackerLog, setAttackerLog] = useState([])
  const [defenderLog, setDefenderLog] = useState([])
  const [centerStatus, setCenterStatus] = useState(null)
  const wsRef = useRef(null)

  const fetchClient = useCallback(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
        if (c?.domains_json) {
          try {
            const domains = JSON.parse(c.domains_json)
            if (domains?.[0]) setTarget(domains[0])
          } catch (_) { /* best-effort; non-fatal */ }
        }
      })
      .catch(() => setClient(null))
  }, [clientId])

  useEffect(() => {
    fetchClient()
  }, [fetchClient])

  const startScan = useCallback(() => {
    const body = {}
    if (target.trim()) body.target = target.trim()
    if (clientId) body.client_id = String(clientId)
    if (aiEndpoint.trim()) body.ai_endpoint = aiEndpoint.trim()
    if (!body.target && !body.client_id) {
      setError(t(`${NS}.no_target_error`))
      return
    }
    setError('')
    setRunning(true)
    setAttackerLog([])
    setDefenderLog([])
    setCenterStatus(null)

    apiFetch('/api/ai-redteam/run', {
      method: 'POST',
      body,
    })
      .then(() => {
        const wsUrl = `${WS_BASE()}/ws/ai-redteam`
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws
        ws.onmessage = (ev) => {
          try {
            const e = JSON.parse(ev.data)
            if (e.phase === 'payload' && e.payload != null) {
              setAttackerLog((prev) => [...prev, { type: 'payload', text: e.payload, index: e.index }])
            }
            if (e.phase === 'response' && e.response != null) {
              setDefenderLog((prev) => [...prev, { type: 'response', text: e.response, index: e.index }])
            }
            if (e.phase === 'judge') {
              setCenterStatus({
                status: e.status || (e.verdict === 'YES' ? 'JAILBREAK_SUCCESS' : 'SECURE'),
                verdict: e.verdict,
                explanation: e.explanation,
              })
              if (e.verdict === 'YES') {
                setAttackerLog((prev) => [...prev, { type: 'judge', text: `✓ JAILBREAK: ${e.explanation || ''}`, index: e.index }])
              } else {
                setAttackerLog((prev) => [...prev, { type: 'judge', text: `✗ SECURE: ${e.explanation || ''}`, index: e.index }])
              }
            }
            if (e.status === 'ANALYZING_RESPONSE') {
              setCenterStatus((prev) => ({ ...prev, status: 'ANALYZING_RESPONSE' }))
            }
          } catch (_) { /* best-effort; non-fatal */ }
        }
        ws.onclose = () => setRunning(false)
        ws.onerror = () => setRunning(false)
      })
      .catch((e) => {
        setError(e?.message || t(`${NS}.start_failed`))
        setRunning(false)
      })
  }, [target, clientId, aiEndpoint, t])

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  return (
    <StandaloneLabShell title={t(`${NS}.title`)} subtitle={t(`${NS}.subtitle`)}>
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
          <div className="lg:col-span-2">
            <label className="block text-[var(--text-tertiary)] text-xs uppercase tracking-wider mb-2">{t(`${NS}.target_label`)}</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t(`${NS}.target_placeholder`)}
              className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white placeholder-[var(--text-muted)]"
              disabled={running}
            />
          </div>
          <div className="lg:col-span-2">
            <label className="block text-[var(--text-tertiary)] text-xs uppercase tracking-wider mb-2">{t(`${NS}.ai_endpoint_label`)}</label>
            <input
              type="text"
              value={aiEndpoint}
              onChange={(e) => setAiEndpoint(e.target.value)}
              placeholder={t(`${NS}.ai_endpoint_placeholder`)}
              className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white placeholder-[var(--text-muted)]"
              disabled={running}
            />
          </div>
        </div>
        <div className="flex gap-2 mb-6">
          <Button variant="unstyled"
            onClick={startScan}
            disabled={running}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-[var(--bg-4)] text-white font-medium text-sm"
          >
            {running ? t(`${NS}.running`) : t(`${NS}.launch`)}
          </Button>
          {clientId && (
            <span className="text-[var(--text-muted)] text-sm self-center">
              {t(`${NS}.client_id`, { id: clientId })}
              {client?.name && ` ${t(`${NS}.client_name`, { name: client.name })}`}
            </span>
          )}
        </div>
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        <div className="mb-6 flex justify-center">
          <div
            className={`rounded-xl border-2 px-6 py-4 min-w-[280px] text-center font-bold text-lg ${
              centerStatus?.status === 'JAILBREAK_SUCCESS'
                ? 'border-red-500 bg-red-500/10 text-red-400'
                : centerStatus?.status === 'SECURE'
                  ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400'
                  : 'border-[var(--border-strong)] bg-[var(--bg-3)]/80 text-[var(--text-secondary)]'
            }`}
          >
            {centerStatus?.status === 'JAILBREAK_SUCCESS' && <>{t(`${NS}.jailbreak_success`)}</>}
            {centerStatus?.status === 'SECURE' && <>{t(`${NS}.secure`)}</>}
            {(centerStatus?.status === 'ANALYZING_RESPONSE' || !centerStatus) && (running ? t(`${NS}.analyzing`) : '—')}
            {centerStatus?.explanation && (
              <p className="text-sm font-normal mt-2 opacity-90">{centerStatus.explanation}</p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 overflow-hidden">
            <div className="bg-rose-900/40 border-b border-[var(--border-default)] px-4 py-2 font-semibold text-rose-300">
              {t(`${NS}.attacker_title`)}
            </div>
            <div className="h-80 overflow-y-auto p-4 font-mono text-sm bg-[var(--bg-0)]/80">
              {attackerLog.length === 0 && (
                <span className="text-[var(--text-muted)]">{t(`${NS}.attacker_empty`)}</span>
              )}
              {attackerLog.map((entry, i) => (
                <div key={i} className="mb-2">
                  {entry.type === 'payload' && (
                    <div className="text-amber-200 break-words">&gt; {entry.text}</div>
                  )}
                  {entry.type === 'judge' && (
                    <div className="text-[var(--text-tertiary)] text-xs mt-1">{entry.text}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-xl bg-[var(--bg-1)]/80 border border-[var(--border-default)]/60 overflow-hidden">
            <div className="bg-[var(--bg-4)]/40 border-b border-[var(--border-default)] px-4 py-2 font-semibold text-[var(--text-secondary)]">
              {t(`${NS}.defender_title`)}
            </div>
            <div className="h-80 overflow-y-auto p-4 font-mono text-sm bg-[var(--bg-0)]/80">
              {defenderLog.length === 0 && (
                <span className="text-[var(--text-muted)]">{t(`${NS}.defender_empty`)}</span>
              )}
              {defenderLog.map((entry, i) => (
                <div key={i} className="mb-2 text-[var(--text-secondary)] break-words">
                  {entry.text}
                </div>
              ))}
            </div>
          </div>
        </div>
        <p className="text-[var(--text-muted)] text-xs mt-4">
          {t(`${NS}.footer`)}
        </p>
    </StandaloneLabShell>
  )
}
