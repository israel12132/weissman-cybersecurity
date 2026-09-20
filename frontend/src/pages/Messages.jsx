import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { MessageSquare, LifeBuoy, Send } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import Avatar from '../components/ui/Avatar'
import Button from '../components/ui/Button'

/**
 * Per-client message + help board. Every employee attached to a client shares
 * one board; a message never leaves its client (server RLS + scope middleware).
 * Staff/owner pick which client's board to open; scoped users are auto-aimed.
 */
export default function Messages() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId, clientScopeLocked } = useClient()

  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [text, setText] = useState('')
  const [asHelp, setAsHelp] = useState(false)
  const [helpOnly, setHelpOnly] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [sending, setSending] = useState(false)
  const listRef = useRef(null)

  const clientId = selectedClientId
  const needsClientPick = !clientScopeLocked && !clientId

  const load = useCallback(async () => {
    if (needsClientPick) {
      setMessages([])
      setLoading(false)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const qs = clientId ? `?client_id=${clientId}&limit=200` : '?limit=200'
      const data = await apiFetch(`/api/messages${qs}`)
      if (!data || data.ok === false) {
        throw new Error(data?.detail || t('pages.messages.load_failed'))
      }
      // API returns newest-first; render oldest-first like a chat.
      setMessages(Array.isArray(data.messages) ? [...data.messages].reverse() : [])
    } catch (e) {
      setError(e.message || t('pages.messages.load_failed'))
    } finally {
      setLoading(false)
    }
  }, [clientId, needsClientPick, t])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight
  }, [messages])

  const visibleMessages = useMemo(() => {
    const base = helpOnly ? messages.filter((m) => m.kind === 'help') : messages
    const q = searchQuery.trim().toLowerCase()
    if (!q) return base
    return base.filter(
      (m) =>
        (m.body || m.text || '').toLowerCase().includes(q) ||
        (m.sender_email || '').toLowerCase().includes(q),
    )
  }, [messages, helpOnly, searchQuery])

  const send = async () => {
    const bodyText = text.trim()
    if (!bodyText || sending) return
    setSending(true)
    setError(null)
    try {
      const body = { body: bodyText, kind: asHelp ? 'help' : 'message' }
      if (clientId) body.client_id = Number(clientId)
      const data = await apiFetch('/api/messages', { method: 'POST', body })
      if (!data || data.ok === false) {
        throw new Error(data?.detail || t('pages.messages.send_failed'))
      }
      setText('')
      setAsHelp(false)
      await load()
    } catch (e) {
      setError(e.message || t('pages.messages.send_failed'))
    } finally {
      setSending(false)
    }
  }

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <PageShell
      title={t('pages.messages.title')}
      subtitle={t('pages.messages.subtitle')}
      icon={<MessageSquare />}
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} />}
    >
      <div className="max-w-3xl mx-auto p-4 sm:p-6 space-y-4">
        {!clientScopeLocked && (
          <div className="flex flex-wrap items-center gap-3">
            <label htmlFor="messages-client" className="text-xs uppercase tracking-widest text-[var(--text-muted)]">
              {t('pages.messages.client')}
            </label>
            <select
              id="messages-client"
              value={clientId || ''}
              onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
              className="px-3 py-2 rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] text-[var(--text-primary)] text-sm focus:border-cyan-500/50 focus:outline-none"
            >
              <option value="">{t('pages.messages.client_placeholder')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name || `Client ${c.id}`}</option>
              ))}
            </select>
          </div>
        )}

        <div className="flex items-center gap-2">
          <Button
            variant="unstyled"
            type="button"
            onClick={() => setHelpOnly(false)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${!helpOnly ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' : 'border-[var(--border-strong)] text-[var(--text-tertiary)]'}`}
          >
            <MessageSquare className="inline w-3.5 h-3.5 mr-1" aria-hidden="true" />
            {t('pages.messages.tab_all')}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={() => setHelpOnly(true)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${helpOnly ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'border-[var(--border-strong)] text-[var(--text-tertiary)]'}`}
          >
            <LifeBuoy className="inline w-3.5 h-3.5 mr-1" aria-hidden="true" />
            {t('pages.messages.tab_help')}
          </Button>
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t('pages.messages.search_placeholder')}
            aria-label={t('common.search')}
            className="ms-auto w-full sm:w-64 px-3 py-1.5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-cyan-500/50 focus:outline-none text-xs"
          />
        </div>

        {error && (
          <div role="alert" className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2.5 rounded-lg text-sm">
            {error}
          </div>
        )}

        <div
          ref={listRef}
          className="h-[52vh] overflow-y-auto rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 space-y-3"
        >
          {needsClientPick ? (
            <p className="text-center text-[var(--text-muted)] text-sm py-8">{t('pages.messages.pick_client')}</p>
          ) : loading ? (
            <p className="text-center text-[var(--text-muted)] text-sm py-8">{t('pages.messages.loading')}</p>
          ) : visibleMessages.length === 0 ? (
            <p className="text-center text-[var(--text-muted)] text-sm py-8">{t('pages.messages.empty')}</p>
          ) : (
            <ol className="space-y-3">
              {visibleMessages.map((m) => (
                <li key={m.id} className="flex gap-2.5">
                  <Avatar name={m.sender_email || '?'} size="sm" className="mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-x-2">
                      <span className="text-xs font-medium text-[var(--text-primary)]">
                        {m.sender_email || t('pages.messages.unknown_sender')}
                      </span>
                      {m.kind === 'help' && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 uppercase tracking-wide">
                          <LifeBuoy className="inline w-3 h-3 mr-0.5" aria-hidden="true" />
                          {t('pages.messages.help_badge')}
                        </span>
                      )}
                      {m.created_at && (
                        <span className="text-[10px] text-[var(--text-muted)]">
                          {new Date(m.created_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 whitespace-pre-wrap break-words text-sm leading-relaxed text-[var(--text-secondary)]">
                      {m.body}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>

        {!needsClientPick && (
          <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-3 space-y-2">
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              placeholder={asHelp ? t('pages.messages.help_placeholder') : t('pages.messages.placeholder')}
              className="w-full resize-none px-3 py-2 rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-cyan-500/50 focus:outline-none text-sm"
            />
            <div className="flex items-center justify-between gap-3">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={asHelp}
                  onChange={(e) => setAsHelp(e.target.checked)}
                  className="rounded border-[var(--border-strong)] bg-[var(--bg-3)] w-4 h-4 accent-amber-500"
                />
                <span className="text-xs text-amber-300 flex items-center gap-1">
                  <LifeBuoy className="w-3.5 h-3.5" aria-hidden="true" />
                  {t('pages.messages.send_as_help')}
                </span>
              </label>
              <Button
                variant="unstyled"
                type="button"
                onClick={send}
                disabled={sending || !text.trim()}
                className="px-4 py-2 rounded-lg font-semibold text-sm bg-cyan-500/20 border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 flex items-center gap-2"
              >
                <Send className="w-4 h-4" aria-hidden="true" />
                {sending ? t('pages.messages.sending') : t('pages.messages.send')}
              </Button>
            </div>
          </div>
        )}
      </div>
    </PageShell>
  )
}
