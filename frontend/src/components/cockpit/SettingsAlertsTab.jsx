import React, { useEffect, useState, Component } from 'react'
import { loadDestructiveConfirmToken, saveDestructiveConfirmToken } from '../../utils/destructiveConfirm'
import { apiFetch } from '../../lib/apiBase'

class SettingsAlertsTabBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch() {
    /* Error boundary — avoid console noise in client-facing builds */
  }

  render() {
    if (this.state.error) {
      const msg = this.state.error?.message || 'Unexpected error'
      return (
        <div className="p-6 text-white/90 max-w-xl mx-auto">
          <h2 className="text-lg font-semibold text-red-400 mb-2">Settings &amp; alerts</h2>
          <p className="text-sm text-white/60 mb-4">
            This tab crashed. You can retry or return to another cockpit view.
          </p>
          <p className="text-xs font-mono text-white/50 break-words mb-4">{msg}</p>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="px-4 py-2 rounded-xl text-sm border border-white/20 text-white/80 hover:bg-white/10"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

function SettingsAlertsTabInner() {
  const [webhookUrl, setWebhookUrl] = useState('')
  const [safeMode, setSafeMode] = useState(false)
  const [destructiveToken, setDestructiveToken] = useState('')
  const [msg, setMsg] = useState(null)
  const [backupMsg, setBackupMsg] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    apiFetch('/api/enterprise/settings')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Load failed'))))
      .then((d) => {
        if (d == null || typeof d !== 'object') return
        setWebhookUrl(typeof d.alert_webhook_url === 'string' ? d.alert_webhook_url : '')
        setSafeMode(!!d.global_safe_mode)
      })
      .catch(() => setMsg({ type: 'err', text: 'Could not load settings' }))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    try {
      setDestructiveToken(loadDestructiveConfirmToken() ?? '')
    } catch {
      setDestructiveToken('')
    }
  }, [])

  const save = async () => {
    setMsg(null)
    try {
      const r = await apiFetch('/api/enterprise/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          global_safe_mode: safeMode,
          alert_webhook_url: webhookUrl,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok) setMsg({ type: 'ok', text: 'Saved' })
      else setMsg({ type: 'err', text: (d && d.detail) || 'Save failed' })
    } catch {
      setMsg({ type: 'err', text: 'Network error' })
    }
  }

  const runBackup = async () => {
    setBackupMsg(null)
    try {
      const r = await apiFetch('/api/system/backup', {
        method: 'POST',
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok && d?.path) setBackupMsg({ type: 'ok', text: `Backup: ${d.path}` })
      else setBackupMsg({ type: 'err', text: (d && d.detail) || 'Backup failed' })
    } catch {
      setBackupMsg({ type: 'err', text: 'Network error' })
    }
  }

  return (
    <div className="p-6 text-white/90 max-w-xl mx-auto">
      <h2 className="text-lg font-semibold mb-1 tracking-tight text-white">Settings &amp; alerts</h2>
      <p className="text-xs text-white/50 mb-6 uppercase tracking-widest">
        Webhooks (Slack / Discord) and optional SMTP via server .env
      </p>
      {loading && <p className="text-sm text-white/40">Loading…</p>}
      {!loading && (
        <div className="space-y-6 rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-6">
          <label className="block">
            <span className="text-xs uppercase tracking-widest text-white/50 block mb-2">
              Alert webhook URL
            </span>
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/... or Discord webhook"
              className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white placeholder:text-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
            <span className="text-[10px] text-white/40 mt-1 block">
              Critical findings with cURL PoE trigger a JSON POST. Override with WEISSMAN_ALERT_WEBHOOK_URL in .env.
            </span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={safeMode}
              onChange={(e) => setSafeMode(e.target.checked)}
              className="rounded border-white/20 bg-black/50 w-4 h-4 accent-[#22d3ee]"
            />
            <span className="text-sm text-white/80">Mirror global safe mode (same as header toggle)</span>
          </label>
          <label className="block">
            <span className="text-xs uppercase tracking-widest text-amber-200/80 block mb-2">
              Destructive action confirm (browser only)
            </span>
            <input
              type="password"
              autoComplete="off"
              value={destructiveToken}
              onChange={(e) => setDestructiveToken(e.target.value)}
              onBlur={() => saveDestructiveConfirmToken(destructiveToken)}
              placeholder="Matches server WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET"
              className="w-full rounded-lg bg-black/50 border border-amber-500/25 px-3 py-2 text-sm text-white placeholder:text-white/30 focus:border-amber-400/50 focus:outline-none"
            />
            <span className="text-[10px] text-white/40 mt-1 block">
              When set on the server, Auto-Heal, containment execute, and deception cloud deploy send header{' '}
              <code className="text-amber-200/70">X-Weissman-Destructive-Confirm</code>. Stored in sessionStorage for this tab only.
            </span>
          </label>
          {msg && (
            <p id="settings-message" className={msg.type === 'ok' ? 'text-emerald-400 text-sm' : 'text-red-400 text-sm'}>{msg.text}</p>
          )}
          <div className="flex flex-wrap gap-3">
            <button
              id="settings-save-btn"
              type="button"
              onClick={save}
              className="px-4 py-2 rounded-xl text-sm font-medium border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20"
            >
              Save settings
            </button>
            <button
              id="settings-backup-btn"
              type="button"
              onClick={runBackup}
              className="px-4 py-2 rounded-xl text-sm font-medium border border-white/20 bg-white/5 text-white/80 hover:bg-white/10"
            >
              Backup database now
            </button>
          </div>
          {backupMsg && (
            <p
              id="settings-backup-message"
              className={
                backupMsg.type === 'ok' ? 'text-emerald-400 text-xs font-mono break-all' : 'text-red-400 text-sm'
              }
            >
              {backupMsg.text}
            </p>
          )}
          <div className="text-[10px] text-white/35 space-y-1 border-t border-white/10 pt-4">
            <p>
              SMTP: set WEISSMAN_SMTP_ENABLED=true plus WEISSMAN_SMTP_HOST, WEISSMAN_SMTP_FROM, WEISSMAN_SMTP_TO (see
              .env.example).
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

export default function SettingsAlertsTab() {
  return (
    <SettingsAlertsTabBoundary>
      <SettingsAlertsTabInner />
    </SettingsAlertsTabBoundary>
  )
}
