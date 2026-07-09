import { useEffect, useState, Component } from 'react'
import { useTranslation } from 'react-i18next'
import { loadDestructiveConfirmToken, saveDestructiveConfirmToken } from '../../utils/destructiveConfirm'
import { apiFetch } from '../../lib/apiBase'

const NS = 'components.cockpitTabs.settingsAlerts'

function SettingsAlertsTabCrashUI({ error, onRetry }) {
  const { t } = useTranslation()
  const msg = error?.message || t(`${NS}.unexpectedError`)
  return (
    <div className="p-6 text-white/90 max-w-xl mx-auto">
      <h2 className="text-lg font-semibold text-red-400 mb-2">{t(`${NS}.crashTitle`)}</h2>
      <p className="text-sm text-white/60 mb-4">{t(`${NS}.crashBody`)}</p>
      <p className="text-xs font-mono text-white/50 break-words mb-4">{msg}</p>
      <button
        type="button"
        onClick={onRetry}
        className="px-4 py-2 rounded-xl text-sm border border-white/20 text-white/80 hover:bg-white/10"
      >
        {t(`${NS}.tryAgain`)}
      </button>
    </div>
  )
}

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
      return (
        <SettingsAlertsTabCrashUI
          error={this.state.error}
          onRetry={() => this.setState({ error: null })}
        />
      )
    }
    return this.props.children
  }
}

function SettingsAlertsTabInner() {
  const { t } = useTranslation()
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
      .catch(() => setMsg({ type: 'err', text: t(`${NS}.loadFailed`) }))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    try {
      setDestructiveToken(loadDestructiveConfirmToken() ?? '')
    } catch {
      setDestructiveToken('')
    }
  }, [t])

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
      if (r.ok) setMsg({ type: 'ok', text: t(`${NS}.saved`) })
      else setMsg({ type: 'err', text: (d && d.detail) || t(`${NS}.saveFailed`) })
    } catch {
      setMsg({ type: 'err', text: t(`${NS}.networkError`) })
    }
  }

  const runBackup = async () => {
    setBackupMsg(null)
    try {
      const r = await apiFetch('/api/system/backup', {
        method: 'POST',
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok && d?.path) setBackupMsg({ type: 'ok', text: t(`${NS}.backupPath`, { path: d.path }) })
      else setBackupMsg({ type: 'err', text: (d && d.detail) || t(`${NS}.backupFailed`) })
    } catch {
      setBackupMsg({ type: 'err', text: t(`${NS}.networkError`) })
    }
  }

  return (
    <div className="p-6 text-white/90 max-w-xl mx-auto">
      <h2 className="text-lg font-semibold mb-1 tracking-tight text-white">{t(`${NS}.title`)}</h2>
      <p className="text-xs text-white/50 mb-6 uppercase tracking-widest">
        {t(`${NS}.subtitle`)}
      </p>
      {loading && <p className="text-sm text-white/40">{t(`${NS}.loading`)}</p>}
      {!loading && (
        <div className="space-y-6 rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-6">
          <label className="block">
            <span className="text-xs uppercase tracking-widest text-white/50 block mb-2">
              {t(`${NS}.webhookLabel`)}
            </span>
            <input
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder={t(`${NS}.webhookPlaceholder`)}
              className="w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white placeholder:text-white/30 focus:border-[#22d3ee]/50 focus:outline-none"
            />
            <span className="text-[10px] text-white/40 mt-1 block">
              {t(`${NS}.webhookHint`)}
            </span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={safeMode}
              onChange={(e) => setSafeMode(e.target.checked)}
              className="rounded border-white/20 bg-black/50 w-4 h-4 accent-[#22d3ee]"
            />
            <span className="text-sm text-white/80">{t(`${NS}.safeModeLabel`)}</span>
          </label>
          <label className="block">
            <span className="text-xs uppercase tracking-widest text-amber-200/80 block mb-2">
              {t(`${NS}.destructiveLabel`)}
            </span>
            <input
              type="password"
              autoComplete="off"
              value={destructiveToken}
              onChange={(e) => setDestructiveToken(e.target.value)}
              onBlur={() => saveDestructiveConfirmToken(destructiveToken)}
              placeholder={t(`${NS}.destructivePlaceholder`)}
              className="w-full rounded-lg bg-black/50 border border-amber-500/25 px-3 py-2 text-sm text-white placeholder:text-white/30 focus:border-amber-400/50 focus:outline-none"
            />
            <span className="text-[10px] text-white/40 mt-1 block">
              {t(`${NS}.destructiveHintBefore`)}
              <code className="text-amber-200/70">X-Weissman-Destructive-Confirm</code>
              {t(`${NS}.destructiveHintAfter`)}
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
              {t(`${NS}.saveSettings`)}
            </button>
            <button
              id="settings-backup-btn"
              type="button"
              onClick={runBackup}
              className="px-4 py-2 rounded-xl text-sm font-medium border border-white/20 bg-white/5 text-white/80 hover:bg-white/10"
            >
              {t(`${NS}.backupDatabase`)}
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
            <p>{t(`${NS}.smtpHint`)}</p>
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
