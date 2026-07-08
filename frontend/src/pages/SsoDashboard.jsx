/**
 * Enterprise SSO Management Dashboard
 *
 * Three-panel workflow:
 *  1. Provider Selection — cards for Okta, Azure AD, Google, Ping, Custom SAML/OIDC
 *  2. Configuration Form — fields tailored to the selected vendor
 *  3. Active IdP Table — list of configured IdPs with status, Test Connection, edit/delete
 */
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EmptyState from '../components/ui/EmptyState'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiUrl } from '../lib/apiBase'
import { api } from '../utils/apiFetch'
import { confirmDialog } from '../utils/confirmDialog'

// ── Provider catalogue ────────────────────────────────────────────────────────

const PROVIDERS = [
  { id: 'okta', protocol: 'oidc', color: '#009ae0', logo: '🔷', fields: ['okta_domain', 'client_id', 'client_secret'] },
  { id: 'azure_ad', protocol: 'oidc', color: '#0078d4', logo: '🪟', fields: ['azure_tenant_id', 'client_id', 'client_secret'] },
  { id: 'google', protocol: 'oidc', color: '#4285f4', logo: '🔵', fields: ['client_id', 'client_secret'] },
  { id: 'ping', protocol: 'oidc', color: '#e4002b', logo: '🔴', fields: ['issuer_url', 'client_id', 'client_secret'] },
  { id: 'saml_custom', protocol: 'saml', color: '#f59e0b', logo: '🔐', fields: ['saml_idp_sso_url', 'saml_idp_cert_pem', 'sp_entity_id'] },
  { id: 'oidc_custom', protocol: 'oidc', color: '#8b5cf6', logo: '🟣', fields: ['issuer_url', 'client_id', 'client_secret'] },
]

const FIELD_META = {
  name: { required: true, type: 'text' },
  okta_domain: { required: true, type: 'text' },
  azure_tenant_id: { required: true, type: 'text' },
  issuer_url: { required: true, type: 'text' },
  client_id: { required: true, type: 'text' },
  client_secret: { required: false, type: 'password', hasNote: true },
  saml_idp_sso_url: { required: true, type: 'text' },
  saml_idp_cert_pem: { required: false, type: 'textarea' },
  sp_entity_id: { required: false, type: 'text' },
  email_claim: { required: false, type: 'text' },
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveIssuerUrl(vendor, form) {
  if (vendor === 'okta' && form.okta_domain) {
    const d = form.okta_domain.trim().replace(/^https?:\/\//, '')
    // Validate domain ends with okta.com or oktapreview.com to prevent SSRF
    if (!d.match(/\.(okta\.com|oktapreview\.com|okta-emea\.com)$/)) {
      return '' // will fail server-side validation; surface error from API
    }
    return `https://${d}`
  }
  if (vendor === 'azure_ad' && form.azure_tenant_id) {
    const tid = form.azure_tenant_id.trim()
    // Must be a GUID or a verified domain — validate GUID format or domain
    const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
    if (!guidPattern.test(tid) && !domainPattern.test(tid)) {
      return ''
    }
    return `https://login.microsoftonline.com/${tid}/v2.0`
  }
  if (vendor === 'google') {
    return 'https://accounts.google.com'
  }
  return form.issuer_url ?? ''
}

// ── Status badge ──────────────────────────────────────────────────────────────

function ActiveBadge({ active, lastOk }) {
  const { t } = useTranslation()
  if (!active) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-disabled)]">{t('pages.ssoDashboard.status_inactive')}</span>
  )
  if (lastOk === true) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-green-500/30 bg-green-900/10 text-green-400">{t('pages.ssoDashboard.status_active_ok')}</span>
  )
  if (lastOk === false) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-amber-500/30 bg-amber-900/10 text-amber-400">{t('pages.ssoDashboard.status_active_failed')}</span>
  )
  return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-900/10 text-cyan-400">{t('pages.ssoDashboard.status_active')}</span>
  )
}

// ── Provider Selection Cards ──────────────────────────────────────────────────

function ProviderCard({ prov, onClick }) {
  const { t } = useTranslation()
  return (
    <motion.button
      type="button"
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className="group text-left rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] hover:border-[var(--border-strong)] p-5 transition-all space-y-3"
    >
      <div className="flex items-center gap-3">
        <span className="text-2xl">{prov.logo}</span>
        <div>
          <p className="font-semibold text-white text-sm">{t(`pages.ssoDashboard.providers.${prov.id}.label`)}</p>
          <p className="text-[10px] font-mono text-[var(--text-disabled)] uppercase">{prov.protocol}</p>
        </div>
      </div>
      <p className="text-[11px] text-[var(--text-muted)]">{t(`pages.ssoDashboard.providers.${prov.id}.description`)}</p>
      <div className="text-[10px] font-mono text-[var(--text-disabled)] group-hover:text-[var(--text-tertiary)] transition-colors">{t('pages.ssoDashboard.configure_card')}</div>
    </motion.button>
  )
}

// ── Configuration Form ────────────────────────────────────────────────────────

function ConfigForm({ prov, initial, onSave, onCancel, saving }) {
  const { t } = useTranslation()
  const [form, setForm] = useState({
    name: initial?.name ?? '',
    okta_domain: initial?.okta_domain ?? '',
    azure_tenant_id: initial?.azure_tenant_id ?? '',
    issuer_url: initial?.issuer_url ?? '',
    client_id: initial?.client_id ?? '',
    client_secret: '',
    saml_idp_sso_url: initial?.saml_idp_sso_url ?? '',
    saml_idp_cert_pem: initial?.saml_idp_cert_pem ?? '',
    sp_entity_id: initial?.sp_entity_id ?? '',
    email_claim: initial?.email_claim ?? 'email',
  })

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const allFields = ['name', ...prov.fields, 'email_claim']

  const handleSubmit = e => {
    e.preventDefault()
    const issuer_url = deriveIssuerUrl(prov.id, form)
    onSave({ ...form, issuer_url, provider: prov.protocol, vendor_hint: prov.id })
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      className="rounded-2xl bg-[var(--bg-3)] backdrop-blur-md border border-[var(--border-strong)] p-6 space-y-5"
    >
      {/* Header */}
      <div className="flex items-center gap-3">
        <span className="text-xl">{prov.logo}</span>
        <div>
          <h3 className="text-sm font-bold text-white">{t('pages.ssoDashboard.configure_sso', { label: t(`pages.ssoDashboard.providers.${prov.id}.label`) })}</h3>
          <p className="text-[10px] font-mono text-[var(--text-disabled)] uppercase">{prov.protocol} · {t(`pages.ssoDashboard.providers.${prov.id}.description`)}</p>
        </div>
        <button type="button" onClick={onCancel} className="ml-auto text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] text-lg transition-colors">✕</button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {allFields.map(key => {
            const meta = FIELD_META[key]
            if (!meta) return null
            const label = t(`pages.ssoDashboard.fields.${key}.label`)
            const placeholder = t(`pages.ssoDashboard.fields.${key}.placeholder`)
            const note = meta.hasNote ? t(`pages.ssoDashboard.fields.${key}.note`) : ''
            if (meta.type === 'textarea') return (
              <div key={key} className="sm:col-span-2 space-y-1">
                <label className="text-[11px] font-mono text-[var(--text-muted)] uppercase">{label}{meta.required && <span className="text-rose-400 ml-0.5">*</span>}</label>
                <textarea
                  rows={5}
                  placeholder={placeholder}
                  value={form[key] ?? ''}
                  onChange={e => set(key, e.target.value)}
                  className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] font-mono text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40 resize-none"
                />
              </div>
            )
            return (
              <div key={key} className={`space-y-1 ${key === 'name' ? 'sm:col-span-2' : ''}`}>
                <label className="text-[11px] font-mono text-[var(--text-muted)] uppercase">
                  {label}{meta.required && <span className="text-rose-400 ml-0.5">*</span>}
                </label>
                <input
                  type={meta.type}
                  placeholder={placeholder}
                  value={form[key] ?? ''}
                  onChange={e => set(key, e.target.value)}
                  required={meta.required && (!initial || !form[key])}
                  className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
                />
                {note && <p className="text-[10px] text-[var(--text-disabled)]">{note}</p>}
              </div>
            )
          })}
        </div>

        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving}
            className="flex-1 px-4 py-2 rounded-xl border border-cyan-500/40 text-cyan-300/80 text-[12px] font-mono uppercase hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {saving ? t('pages.ssoDashboard.saving') : initial ? t('pages.ssoDashboard.update_connection') : t('pages.ssoDashboard.add_connection_btn')}
          </button>
          <button type="button" onClick={onCancel} className="px-4 py-2 rounded-xl border border-[var(--border-default)] text-[var(--text-muted)] text-[12px] font-mono hover:border-[var(--border-strong)] transition-all">
            {t('pages.ssoDashboard.cancel')}
          </button>
        </div>
      </form>
    </motion.div>
  )
}

// ── IdP Table Row ─────────────────────────────────────────────────────────────

function IdpRow({ idp, onEdit, onDelete, onToggle, onTest, testing }) {
  const { t } = useTranslation()
  const prov = PROVIDERS.find(p => p.id === idp.vendor_hint) ?? PROVIDERS[5]

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-4 flex flex-col sm:flex-row sm:items-center gap-4"
    >
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <span className="text-xl shrink-0">{prov.logo}</span>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white truncate">{idp.name}</p>
          <p className="text-[10px] font-mono text-[var(--text-disabled)] truncate">{idp.issuer_url || idp.saml_idp_sso_url || '—'}</p>
          {idp.last_test_at && (
            <p className="text-[10px] text-[var(--text-disabled)] mt-0.5">
              {t('pages.ssoDashboard.last_tested', { time: new Date(idp.last_test_at).toLocaleString() })}
              {idp.last_test_error && <span className="text-rose-400/70 ml-1">— {idp.last_test_error.slice(0, 60)}</span>}
            </p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap shrink-0">
        <ActiveBadge active={idp.active} lastOk={idp.last_test_ok} />

        <button
          type="button"
          disabled={testing}
          onClick={() => onTest(idp.id)}
          className="text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-cyan-300/70 hover:border-cyan-500/30 px-2.5 py-1 rounded-xl transition-all disabled:opacity-40"
        >
          {testing ? t('pages.ssoDashboard.testing') : t('pages.ssoDashboard.test_btn')}
        </button>
        <button
          type="button"
          onClick={() => onToggle(idp.id)}
          className={`text-[11px] font-mono border px-2.5 py-1 rounded-xl transition-all ${
            idp.active
              ? 'border-amber-500/20 text-amber-400/60 hover:bg-amber-900/20'
              : 'border-green-500/20 text-green-400/60 hover:bg-green-900/20'
          }`}
        >
          {idp.active ? t('pages.ssoDashboard.disable') : t('pages.ssoDashboard.enable')}
        </button>
        <button
          type="button"
          onClick={() => onEdit(idp)}
          className="text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] px-2.5 py-1 rounded-xl transition-all"
        >
          {t('pages.ssoDashboard.edit')}
        </button>
        <button
          type="button"
          onClick={() => onDelete(idp.id)}
          className="text-[11px] font-mono border border-rose-500/20 text-rose-400/50 hover:bg-rose-900/20 px-2.5 py-1 rounded-xl transition-all"
        >
          ✕
        </button>
      </div>
    </motion.div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SsoDashboard() {
  const { t } = useTranslation()
  const [idps, setIdps] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedProv, setSelectedProv] = useState(null)
  const [editingIdp, setEditingIdp] = useState(null)
  const [saving, setSaving] = useState(false)
  const [testingId, setTestingId] = useState(null)
  const [toast, setToast] = useState(null)

  const showToast = useCallback((msg, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 4500)
  }, [])

  const fetchIdps = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.get('/api/sso/idps')
      setIdps(data.idps ?? [])
    } catch (e) {
      showToast(t('pages.ssoDashboard.load_failed', { message: e.message }), false)
    } finally {
      setLoading(false)
    }
  }, [showToast, t])

  useEffect(() => { fetchIdps() }, [fetchIdps])

  const handleSave = useCallback(async (formData) => {
    setSaving(true)
    try {
      if (editingIdp) {
        await api.patch(`/api/sso/idps/${editingIdp.id}`, formData)
        showToast(t('pages.ssoDashboard.connection_updated'))
      } else {
        await api.post('/api/sso/idps', formData)
        showToast(t('pages.ssoDashboard.connection_created'))
      }
      setSelectedProv(null)
      setEditingIdp(null)
      await fetchIdps()
    } catch (e) {
      showToast(t('pages.ssoDashboard.save_failed', { message: e.message }), false)
    } finally {
      setSaving(false)
    }
  }, [editingIdp, fetchIdps, showToast, t])

  const handleDelete = useCallback(async (id) => {
    if (!window.confirm(t('pages.ssoDashboard.delete_confirm'))) return
    try {
      await api.delete(`/api/sso/idps/${id}`)
      showToast(t('pages.ssoDashboard.connection_removed'))
      await fetchIdps()
    } catch (e) {
      showToast(t('pages.ssoDashboard.delete_failed', { message: e.message }), false)
    }
  }, [fetchIdps, showToast, t])

  const handleToggle = useCallback(async (id) => {
    try {
      const data = await api.post(`/api/sso/idps/${id}/toggle`)
      setIdps(prev => prev.map(i => i.id === id ? { ...i, active: data.active } : i))
    } catch (e) {
      showToast(t('pages.ssoDashboard.toggle_failed', { message: e.message }), false)
    }
  }, [showToast, t])

  const handleTest = useCallback(async (id) => {
    setTestingId(id)
    try {
      const data = await api.post(`/api/sso/idps/${id}/test`)
      if (data.ok) {
        showToast(t('pages.ssoDashboard.test_passed'))
      } else {
        showToast(t('pages.ssoDashboard.test_failed', { message: data.error ?? 'unknown error' }), false)
      }
      await fetchIdps()
    } catch (e) {
      showToast(t('pages.ssoDashboard.test_failed', { message: e.message }), false)
    } finally {
      setTestingId(null)
    }
  }, [fetchIdps, showToast, t])

  const handleEdit = useCallback((idp) => {
    const prov = PROVIDERS.find(p => p.id === idp.vendor_hint) ?? PROVIDERS[5]
    setEditingIdp(idp)
    setSelectedProv(prov)
  }, [])

  const cancelForm = () => { setSelectedProv(null); setEditingIdp(null) }

  const showForm = selectedProv !== null

  const listFindings = useMemo(() => idps.map((idp) => ({
    id: idp.id,
    severity: idp.enabled === false ? 'medium' : 'info',
    title: idp.name || idp.vendor_hint || idp.id,
    type: idp.vendor_hint || 'idp',
    description: idp.entity_id || idp.issuer || '',
  })), [idps])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-sso-idps',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  const visibleIdps = useMemo(() => {
    if (!searchQuery.trim()) return idps
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return idps.filter((idp) => ids.has(String(idp.id)))
  }, [idps, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t('pages.ssoDashboard.title')}
      badge={t('pages.ssoDashboard.badge')}
      badgeColor="#8b5cf6"
      subtitle={t('pages.ssoDashboard.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={fetchIdps}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="max-w-5xl mx-auto space-y-10">

        {/* Header */}
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-white">{t('pages.ssoDashboard.title')}</h2>
          <p className="text-[12px] text-[var(--text-muted)]">
            {t('pages.ssoDashboard.header_detail')}
          </p>
        </div>

        {/* Provider selection grid — hidden while form is open */}
        <AnimatePresence>
          {!showForm && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono text-[var(--text-muted)] uppercase tracking-widest">{t('pages.ssoDashboard.add_connection')}</h3>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                {PROVIDERS.map(prov => (
                  <ProviderCard key={prov.id} prov={prov} onClick={() => { setEditingIdp(null); setSelectedProv(prov) }} />
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Configuration form */}
        <AnimatePresence>
          {showForm && selectedProv && (
            <ConfigForm
              prov={selectedProv}
              initial={editingIdp}
              onSave={handleSave}
              onCancel={cancelForm}
              saving={saving}
            />
          )}
        </AnimatePresence>

        {/* Configured connections */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono text-[var(--text-muted)] uppercase tracking-widest">
              {t('pages.ssoDashboard.configured_connections')}
              {idps.length > 0 && <span className="ml-2 text-[var(--text-disabled)]">{t('pages.ssoDashboard.connection_count', { count: idps.length })}</span>}
            </h3>
            <button
              type="button"
              onClick={fetchIdps}
              className="text-[11px] font-mono border border-[var(--border-default)] text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] hover:border-[var(--border-strong)] px-2.5 py-1 rounded-xl transition-all"
            >
              {t('pages.ssoDashboard.refresh')}
            </button>
          </div>

          {loading && (
            <p className="text-[11px] text-[var(--text-disabled)] font-mono animate-pulse">{t('pages.ssoDashboard.loading')}</p>
          )}

          {!loading && idps.length > 0 && (
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleIdps.length}
              totalCount={idps.length}
            />
          )}

          <AnimatePresence>
            {!loading && idps.length === 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="rounded-2xl border border-dashed border-[var(--border-default)] p-10 text-center"
              >
                <p className="text-[var(--text-disabled)] text-[12px]">{t('pages.ssoDashboard.no_idps')}</p>
                <p className="text-[var(--text-disabled)] text-[11px] mt-1">{t('pages.ssoDashboard.no_idps_hint')}</p>
              </motion.div>
            )}
            {!loading && idps.length > 0 && visibleIdps.length === 0 && (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
                compact
              />
            )}
            {visibleIdps.map(idp => (
              <IdpRow
                key={idp.id}
                idp={idp}
                onEdit={handleEdit}
                onDelete={handleDelete}
                onToggle={handleToggle}
                onTest={handleTest}
                testing={testingId === idp.id}
              />
            ))}
          </AnimatePresence>
        </div>

        {/* SP Metadata info */}
        <div className="rounded-2xl bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] px-5 py-4 space-y-2">
          <h4 className="text-[11px] font-mono text-[var(--text-muted)] uppercase">{t('pages.ssoDashboard.sp_metadata')}</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              { label: t('pages.ssoDashboard.oidc_callback'), value: apiUrl('/api/auth/oidc/callback') },
              { label: t('pages.ssoDashboard.saml_acs'), value: apiUrl('/api/auth/saml/acs') },
              { label: t('pages.ssoDashboard.oidc_login'), value: `${apiUrl('/api/auth/oidc/begin')}?tenant_slug=TENANT&idp_name=NAME` },
              { label: t('pages.ssoDashboard.saml_login'), value: `${apiUrl('/api/auth/saml/begin')}?tenant_slug=TENANT&idp_name=NAME` },
            ].map(item => (
              <div key={item.label} className="space-y-0.5">
                <p className="text-[9px] font-mono text-[var(--text-disabled)] uppercase">{item.label}</p>
                <code className="text-[10px] font-mono text-cyan-400/50 break-all">{item.value}</code>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 16 }}
            className={`fixed bottom-6 right-6 px-4 py-3 rounded-2xl border text-[12px] font-mono z-50 max-w-sm ${
              toast.ok
                ? 'bg-green-900/40 border-green-500/30 text-green-300'
                : 'bg-red-900/40 border-red-500/30 text-red-300'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>
    </PageShell>
  )
}
