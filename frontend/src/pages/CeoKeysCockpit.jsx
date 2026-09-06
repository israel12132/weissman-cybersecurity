import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  AlertTriangle,
  Check,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch'
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'
import useFocusTrap from '../hooks/useFocusTrap'

const NS = 'pages.ceoKeysCockpit'
const CATEGORIES = ['core', 'auth', 'llm', 'intel', 'notify', 'crypto', 'oast', 'cicd', 'cloud', 'billing', 'ops', 'custom']

function statusSeverity(key) {
  if (!key.configured && key.tier === 'required') return 'critical'
  if (!key.configured && key.tier === 'recommended') return 'high'
  if (!key.configured) return 'medium'
  return 'info'
}

export default function CeoKeysCockpit() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [payload, setPayload] = useState({ keys: [], summary: {} })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [category, setCategory] = useState('all')
  const [filter, setFilter] = useState('all')
  const [modal, setModal] = useState(null)
  const [revealed, setRevealed] = useState({})
  const [copied, setCopied] = useState(null)
  const modalRef = useRef(null)
  useFocusTrap(modalRef, !!modal)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.get('/api/ceo/platform-keys')
      setPayload({
        keys: Array.isArray(data.keys) ? data.keys : [],
        summary: data.summary || {},
      })
    } catch (err) {
      setError(err.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const keys = payload.keys
  const summary = payload.summary || {}

  const listFindings = useMemo(
    () =>
      keys.map((k) => ({
        id: k.env_name,
        severity: statusSeverity(k),
        title: k.env_name,
        type: k.category,
        description: `${k.tier} ${k.custom ? 'custom' : ''} ${k.configured ? 'armed' : 'missing'}`,
        resource: (k.aliases || []).join(' '),
      })),
    [keys],
  )

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-classified-keys',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleKeys = useMemo(() => {
    const ids = new Set(filteredFindings.map((f) => f.id))
    return keys.filter((k) => {
      if (searchQuery.trim() && !ids.has(k.env_name)) return false
      if (category !== 'all' && k.category !== category) return false
      if (filter === 'missing' && k.configured) return false
      if (filter === 'armed' && !k.configured) return false
      if (filter === 'required' && k.tier !== 'required') return false
      return true
    })
  }, [keys, filteredFindings, searchQuery, category, filter])

  const openAdd = (key) => {
    setModal({
      env_name: key?.env_name || '',
      value: '',
      custom: !key || key.custom,
      rotating: Boolean(key?.configured),
    })
    setRevealed((prev) => ({ ...prev, __modal: false }))
  }

  const saveKey = async (e) => {
    e.preventDefault()
    const env_name = (modal.env_name || '').trim()
    const value = modal.value || ''
    if (!env_name || !value.trim()) {
      toast.error(t(`${NS}.name_value_required`))
      return
    }
    try {
      const data = await api.put('/api/ceo/platform-keys', { env_name, value })
      setPayload({
        keys: Array.isArray(data.keys) ? data.keys : [],
        summary: data.summary || {},
      })
      setModal(null)
      toast.success(t(`${NS}.saved`))
    } catch (err) {
      toast.error(err.message || t(`${NS}.save_failed`))
    }
  }

  const revealKey = async (envName) => {
    if (revealed[envName]) {
      setRevealed((prev) => ({ ...prev, [envName]: undefined }))
      return
    }
    try {
      const data = await api.post(`/api/ceo/platform-keys/${encodeURIComponent(envName)}/reveal`)
      setRevealed((prev) => ({ ...prev, [envName]: data.value || '' }))
    } catch (err) {
      toast.error(err.message || t(`${NS}.reveal_failed`))
    }
  }

  const copyKey = async (envName) => {
    let value = revealed[envName]
    if (!value) {
      try {
        const data = await api.post(`/api/ceo/platform-keys/${encodeURIComponent(envName)}/reveal`)
        value = data.value || ''
        setRevealed((prev) => ({ ...prev, [envName]: value }))
      } catch (err) {
        toast.error(err.message || t(`${NS}.reveal_failed`))
        return
      }
    }
    await navigator.clipboard.writeText(value)
    setCopied(envName)
    setTimeout(() => setCopied(null), 2000)
  }

  const removeFromKeyring = async (envName) => {
    const ok = await confirmDialog({
      title: t(`${NS}.delete_title`),
      message: t(`${NS}.delete_confirm`, { name: envName }),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    })
    if (!ok) return
    try {
      const data = await api.delete(`/api/ceo/platform-keys/${encodeURIComponent(envName)}`)
      setPayload({
        keys: Array.isArray(data.keys) ? data.keys : [],
        summary: data.summary || {},
      })
      toast.success(t(`${NS}.deleted`))
    } catch (err) {
      toast.error(err.message || t(`${NS}.delete_failed`))
    }
  }

  const missingRequired = summary.required_missing || 0

  return (
    <PageShell
      title={t(`${NS}.title`)}
      icon={<KeyRound />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <div className="relative overflow-hidden rounded-2xl border border-amber-500/30 bg-gradient-to-br from-amber-950/40 via-[var(--bg-2)] to-cyan-950/30 p-5">
          <div className="pointer-events-none absolute -end-8 -top-10 h-40 w-40 rounded-full bg-amber-400/10 blur-3xl" />
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-[10px] font-mono uppercase tracking-[0.28em] text-amber-300/90">
                {t(`${NS}.classified_banner`)}
              </p>
              <h2 className="mt-1 text-xl font-semibold text-white tracking-tight">
                {t(`${NS}.headline`)}
              </h2>
              <p className="mt-2 max-w-2xl text-sm text-[var(--text-secondary)]">
                {t(`${NS}.subtitle`)}
              </p>
            </div>
            <Button
              variant="unstyled"
              onClick={() => openAdd(null)}
              className="inline-flex items-center gap-2 rounded-lg bg-amber-400 px-4 py-2.5 text-sm font-semibold text-black hover:bg-amber-300 transition-colors"
            >
              <Plus className="w-4 h-4" />
              {t(`${NS}.add_any`)}
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Kpi
            label={t(`${NS}.kpi_total`)}
            value={summary.total ?? '—'}
            color="text-cyan-300"
            icon={<KeyRound className="w-4 h-4 text-cyan-400" />}
          />
          <Kpi
            label={t(`${NS}.kpi_armed`)}
            value={summary.armed ?? '—'}
            color="text-emerald-300"
            icon={<Lock className="w-4 h-4 text-emerald-400" />}
          />
          <Kpi
            label={t(`${NS}.kpi_missing`)}
            value={summary.missing ?? '—'}
            color="text-amber-300"
            icon={<AlertTriangle className="w-4 h-4 text-amber-400" />}
          />
          <Kpi
            label={t(`${NS}.kpi_required_missing`)}
            value={missingRequired}
            color={missingRequired ? 'text-rose-300' : 'text-emerald-300'}
            icon={<ShieldAlert className={`w-4 h-4 ${missingRequired ? 'text-rose-400' : 'text-emerald-400'}`} />}
          />
        </div>

        <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)] space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-amber-400" />
                {t(`${NS}.inventory`)}
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {['all', 'missing', 'armed', 'required'].map((id) => (
                  <Button
                    key={id}
                    variant="unstyled"
                    onClick={() => setFilter(id)}
                    className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase tracking-wider border ${
                      filter === id
                        ? 'border-amber-400/50 bg-amber-500/15 text-amber-100'
                        : 'border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {t(`${NS}.filter_${id}`)}
                  </Button>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Chip active={category === 'all'} onClick={() => setCategory('all')}>
                {t(`${NS}.cat_all`)}
              </Chip>
              {CATEGORIES.map((id) => (
                <Chip key={id} active={category === id} onClick={() => setCategory(id)}>
                  {t(`${NS}.cat_${id}`)}
                </Chip>
              ))}
            </div>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleKeys.length}
              totalCount={keys.length}
              searchPlaceholder={t(`${NS}.search_placeholder`)}
            />
          </div>

          {loading ? (
            <div className="p-10 text-center text-[var(--text-muted)]">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-3 text-amber-400" />
              {t(`${NS}.loading`)}
            </div>
          ) : error ? (
            <div className="p-8 text-center text-rose-300 text-sm">{error}</div>
          ) : visibleKeys.length === 0 ? (
            <div className="p-8 text-center text-[var(--text-muted)]">{t(`${NS}.empty_filter`)}</div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {visibleKeys.map((key) => (
                <KeyRow
                  key={key.env_name}
                  item={key}
                  t={t}
                  revealed={revealed[key.env_name]}
                  copied={copied === key.env_name}
                  onAdd={() => openAdd(key)}
                  onReveal={() => revealKey(key.env_name)}
                  onCopy={() => copyKey(key.env_name)}
                  onDelete={() => removeFromKeyring(key.env_name)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <form
            ref={modalRef}
            onSubmit={saveKey}
            className="w-full max-w-lg rounded-2xl border border-amber-500/30 bg-[var(--bg-elevated)] p-5 space-y-4 shadow-2xl"
            role="dialog"
            aria-modal="true"
            aria-labelledby="ceo-keys-modal-title"
          >
            <h3 id="ceo-keys-modal-title" className="text-lg font-semibold text-white">
              {modal.rotating ? t(`${NS}.rotate_title`) : t(`${NS}.add_title`)}
            </h3>
            <label className="block space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                {t(`${NS}.env_name`)}
              </span>
              <input
                value={modal.env_name}
                onChange={(e) => setModal((m) => ({ ...m, env_name: e.target.value.toUpperCase() }))}
                className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--scrim)] px-3 py-2 font-mono text-sm text-white"
                placeholder={t(`${NS}.env_placeholder`)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="block space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                {t(`${NS}.secret_value`)}
              </span>
              <div className="relative">
                <input
                  type={revealed.__modal ? 'text' : 'password'}
                  value={modal.value}
                  onChange={(e) => setModal((m) => ({ ...m, value: e.target.value }))}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--scrim)] px-3 py-2 pe-10 font-mono text-sm text-white"
                  placeholder={t(`${NS}.value_placeholder`)}
                  autoComplete="off"
                />
                <Button
                  type="button"
                  variant="unstyled"
                  className="absolute end-2 top-1/2 -translate-y-1/2 text-[var(--text-muted)]"
                  onClick={() => setRevealed((p) => ({ ...p, __modal: !p.__modal }))}
                  aria-label={t(`${NS}.toggle_visibility`)}
                >
                  {revealed.__modal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </Button>
              </div>
            </label>
            <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.save_hint`)}</p>
            <div className="flex justify-end gap-2 pt-1">
              <Button type="button" variant="unstyled" className="px-3 py-2 text-sm text-[var(--text-secondary)]" onClick={() => setModal(null)}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="unstyled" className="px-4 py-2 rounded-lg bg-amber-400 text-black text-sm font-semibold">
                {t(`${NS}.save`)}
              </Button>
            </div>
          </form>
        </div>
      )}
    </PageShell>
  )
}

function Kpi({ label, value, color, icon }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
        {icon}
      </div>
      <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
    </div>
  )
}

function Chip({ active, onClick, children }) {
  return (
    <Button
      variant="unstyled"
      onClick={onClick}
      className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wider border ${
        active
          ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-100'
          : 'border-[var(--border-subtle)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
      }`}
    >
      {children}
    </Button>
  )
}

function KeyRow({ item, t, revealed, copied, onAdd, onReveal, onCopy, onDelete }) {
  const armed = item.configured
  return (
    <div className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors">
      <div className="flex flex-col lg:flex-row lg:items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <code className="text-sm font-semibold text-white font-mono">{item.env_name}</code>
            <span
              className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wider border ${
                armed
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : item.tier === 'required'
                    ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                    : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
              }`}
            >
              {armed ? t(`${NS}.armed`) : t(`${NS}.missing`)}
            </span>
            <span className="px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wider border border-[var(--border-default)] text-[var(--text-muted)]">
              {t(`${NS}.cat_${item.category}`, item.category)}
            </span>
            <span className="px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wider border border-[var(--border-default)] text-[var(--text-muted)]">
              {t(`${NS}.tier_${item.tier}`)}
            </span>
            {item.requires_restart && (
              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wider border border-violet-500/30 text-violet-300">
                {t(`${NS}.restart`)}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-2">
            <input
              readOnly
              type={revealed ? 'text' : 'password'}
              value={
                revealed
                  || item.preview
                  || (armed ? (item.last4 ? `••••${item.last4}` : '••••••••') : t(`${NS}.not_set`))
              }
              className="flex-1 min-w-0 rounded-lg border border-[var(--border-default)] bg-[var(--scrim)] px-3 py-2 font-mono text-xs text-white"
            />
            {armed && (
              <>
                <IconBtn onClick={onReveal} label={t(`${NS}.toggle_visibility`)}>
                  {revealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </IconBtn>
                <IconBtn onClick={onCopy} label={t(`${NS}.copy`)}>
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </IconBtn>
              </>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-3 text-[11px] font-mono text-[var(--text-muted)]">
            {item.sources?.length > 0 && (
              <span>{t(`${NS}.sources`, { list: item.sources.join(', ') })}</span>
            )}
            {item.value_len != null && armed && <span>{t(`${NS}.length`, { n: item.value_len })}</span>}
            {item.aliases?.length > 0 && (
              <span>{t(`${NS}.aliases`, { list: item.aliases.join(', ') })}</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="unstyled"
            onClick={onAdd}
            className={`px-3 py-2 rounded-lg text-xs font-semibold ${
              armed
                ? 'bg-cyan-500/15 text-cyan-200 border border-cyan-500/30 hover:bg-cyan-500/25'
                : 'bg-amber-400 text-black hover:bg-amber-300'
            }`}
          >
            {armed ? t(`${NS}.rotate`) : t(`${NS}.add`)}
          </Button>
          {item.in_keyring && (
            <IconBtn onClick={onDelete} label={t('common.delete')} danger>
              <Trash2 className="w-4 h-4" />
            </IconBtn>
          )}
        </div>
      </div>
    </div>
  )
}

function IconBtn({ onClick, label, children, danger }) {
  return (
    <Button
      type="button"
      variant="unstyled"
      onClick={onClick}
      aria-label={label}
      className={`p-2 rounded-lg border ${
        danger
          ? 'bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-500/20'
          : 'bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border-[var(--border-default)] hover:text-white'
      }`}
    >
      {children}
    </Button>
  )
}
