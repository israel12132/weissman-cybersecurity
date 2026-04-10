/**
 * Enterprise SSO Management Dashboard
 *
 * Three-panel workflow:
 *  1. Provider Selection — cards for Okta, Azure AD, Google, Ping, Custom SAML/OIDC
 *  2. Configuration Form — fields tailored to the selected vendor
 *  3. Active IdP Table — list of configured IdPs with status, Test Connection, edit/delete
 */
import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

// ── Provider catalogue ────────────────────────────────────────────────────────

const PROVIDERS = [
  {
    id: 'okta',
    label: 'Okta',
    protocol: 'oidc',
    color: '#009ae0',
    logo: '🔷',
    description: 'Workforce Identity Cloud',
    fields: ['okta_domain', 'client_id', 'client_secret'],
  },
  {
    id: 'azure_ad',
    label: 'Azure AD',
    protocol: 'oidc',
    color: '#0078d4',
    logo: '🪟',
    description: 'Microsoft Entra ID',
    fields: ['azure_tenant_id', 'client_id', 'client_secret'],
  },
  {
    id: 'google',
    label: 'Google Workspace',
    protocol: 'oidc',
    color: '#4285f4',
    logo: '🔵',
    description: 'Google Cloud Identity',
    fields: ['client_id', 'client_secret'],
  },
  {
    id: 'ping',
    label: 'Ping Identity',
    protocol: 'oidc',
    color: '#e4002b',
    logo: '🔴',
    description: 'PingFederate / PingOne',
    fields: ['issuer_url', 'client_id', 'client_secret'],
  },
  {
    id: 'saml_custom',
    label: 'Custom SAML 2.0',
    protocol: 'saml',
    color: '#f59e0b',
    logo: '🔐',
    description: 'Any SAML 2.0 Identity Provider',
    fields: ['saml_idp_sso_url', 'saml_idp_cert_pem', 'sp_entity_id'],
  },
  {
    id: 'oidc_custom',
    label: 'Custom OIDC',
    protocol: 'oidc',
    color: '#8b5cf6',
    logo: '🟣',
    description: 'Any OpenID Connect provider',
    fields: ['issuer_url', 'client_id', 'client_secret'],
  },
]

// ── Field definitions ─────────────────────────────────────────────────────────

const FIELD_DEFS = {
  name:              { label: 'Connection Name',      placeholder: 'e.g. Okta Production', required: true, type: 'text' },
  okta_domain:       { label: 'Okta Domain',          placeholder: 'company.okta.com', required: true, type: 'text' },
  azure_tenant_id:   { label: 'Azure Tenant ID',      placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', required: true, type: 'text' },
  issuer_url:        { label: 'Issuer / Discovery URL',placeholder: 'https://idp.example.com', required: true, type: 'text' },
  client_id:         { label: 'Client ID',             placeholder: 'OAuth 2.0 Client ID', required: true, type: 'text' },
  client_secret:     { label: 'Client Secret',         placeholder: '••••••••', required: false, type: 'password', note: 'Leave blank to keep existing' },
  saml_idp_sso_url:  { label: 'IdP SSO URL / Metadata URL', placeholder: 'https://idp.example.com/metadata.xml', required: true, type: 'text' },
  saml_idp_cert_pem: { label: 'IdP Certificate (PEM)',placeholder: '-----BEGIN CERTIFICATE-----\n...', required: false, type: 'textarea' },
  sp_entity_id:      { label: 'SP Entity ID',          placeholder: 'https://app.weissman.io (leave blank for default)', required: false, type: 'text' },
  email_claim:       { label: 'Email Claim',           placeholder: 'email', required: false, type: 'text' },
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveIssuerUrl(vendor, form) {
  if (vendor === 'okta' && form.okta_domain) {
    const d = form.okta_domain.trim().replace(/^https?:\/\//, '')
    return `https://${d}`
  }
  if (vendor === 'azure_ad' && form.azure_tenant_id) {
    return `https://login.microsoftonline.com/${form.azure_tenant_id.trim()}/v2.0`
  }
  if (vendor === 'google') {
    return 'https://accounts.google.com'
  }
  return form.issuer_url ?? ''
}

// ── Status badge ──────────────────────────────────────────────────────────────

function ActiveBadge({ active, lastOk }) {
  if (!active) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-white/10 text-white/30">Inactive</span>
  )
  if (lastOk === true) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-green-500/30 bg-green-900/10 text-green-400">✓ Active</span>
  )
  if (lastOk === false) return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-amber-500/30 bg-amber-900/10 text-amber-400">⚠ Active / Test Failed</span>
  )
  return (
    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-900/10 text-cyan-400">Active</span>
  )
}

// ── Provider Selection Cards ──────────────────────────────────────────────────

function ProviderCard({ prov, onClick }) {
  return (
    <motion.button
      type="button"
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className="group text-left rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 hover:border-white/25 p-5 transition-all space-y-3"
    >
      <div className="flex items-center gap-3">
        <span className="text-2xl">{prov.logo}</span>
        <div>
          <p className="font-semibold text-white text-sm">{prov.label}</p>
          <p className="text-[10px] font-mono text-white/30 uppercase">{prov.protocol}</p>
        </div>
      </div>
      <p className="text-[11px] text-white/45">{prov.description}</p>
      <div className="text-[10px] font-mono text-white/20 group-hover:text-white/50 transition-colors">→ Configure</div>
    </motion.button>
  )
}

// ── Configuration Form ────────────────────────────────────────────────────────

function ConfigForm({ prov, initial, onSave, onCancel, saving }) {
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
      className="rounded-2xl bg-black/50 backdrop-blur-md border border-white/15 p-6 space-y-5"
    >
      {/* Header */}
      <div className="flex items-center gap-3">
        <span className="text-xl">{prov.logo}</span>
        <div>
          <h3 className="text-sm font-bold text-white">{prov.label} — Configure SSO</h3>
          <p className="text-[10px] font-mono text-white/30 uppercase">{prov.protocol} · {prov.description}</p>
        </div>
        <button type="button" onClick={onCancel} className="ml-auto text-white/30 hover:text-white/60 text-lg transition-colors">✕</button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {allFields.map(key => {
            const def = FIELD_DEFS[key]
            if (!def) return null
            if (def.type === 'textarea') return (
              <div key={key} className="sm:col-span-2 space-y-1">
                <label className="text-[11px] font-mono text-white/40 uppercase">{def.label}{def.required && <span className="text-rose-400 ml-0.5">*</span>}</label>
                <textarea
                  rows={5}
                  placeholder={def.placeholder}
                  value={form[key] ?? ''}
                  onChange={e => set(key, e.target.value)}
                  className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] font-mono text-white/70 placeholder-white/20 focus:outline-none focus:border-cyan-500/40 resize-none"
                />
              </div>
            )
            return (
              <div key={key} className={`space-y-1 ${key === 'name' ? 'sm:col-span-2' : ''}`}>
                <label className="text-[11px] font-mono text-white/40 uppercase">
                  {def.label}{def.required && <span className="text-rose-400 ml-0.5">*</span>}
                </label>
                <input
                  type={def.type}
                  placeholder={def.placeholder}
                  value={form[key] ?? ''}
                  onChange={e => set(key, e.target.value)}
                  required={def.required && !initial}
                  className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
                />
                {def.note && <p className="text-[10px] text-white/25">{def.note}</p>}
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
            {saving ? '⟳ Saving…' : initial ? '↺ Update Connection' : '＋ Add Connection'}
          </button>
          <button type="button" onClick={onCancel} className="px-4 py-2 rounded-xl border border-white/10 text-white/40 text-[12px] font-mono hover:border-white/20 transition-all">
            Cancel
          </button>
        </div>
      </form>
    </motion.div>
  )
}

// ── IdP Table Row ─────────────────────────────────────────────────────────────

function IdpRow({ idp, onEdit, onDelete, onToggle, onTest, testing }) {
  const prov = PROVIDERS.find(p => p.id === idp.vendor_hint) ?? PROVIDERS[5]

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4 flex flex-col sm:flex-row sm:items-center gap-4"
    >
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <span className="text-xl shrink-0">{prov.logo}</span>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white truncate">{idp.name}</p>
          <p className="text-[10px] font-mono text-white/30 truncate">{idp.issuer_url || idp.saml_idp_sso_url || '—'}</p>
          {idp.last_test_at && (
            <p className="text-[10px] text-white/20 mt-0.5">
              Last tested: {new Date(idp.last_test_at).toLocaleString()}
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
          className="text-[11px] font-mono border border-white/10 text-white/40 hover:text-cyan-300/70 hover:border-cyan-500/30 px-2.5 py-1 rounded-xl transition-all disabled:opacity-40"
        >
          {testing ? '⟳' : '⚡ Test'}
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
          {idp.active ? 'Disable' : 'Enable'}
        </button>
        <button
          type="button"
          onClick={() => onEdit(idp)}
          className="text-[11px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 px-2.5 py-1 rounded-xl transition-all"
        >
          Edit
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
      const data = await apiFetch('/api/sso/idps')
      setIdps(data.idps ?? [])
    } catch (e) {
      showToast('Failed to load IdPs: ' + e.message, false)
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => { fetchIdps() }, [fetchIdps])

  const handleSave = useCallback(async (formData) => {
    setSaving(true)
    try {
      if (editingIdp) {
        await apiFetch(`/api/sso/idps/${editingIdp.id}`, { method: 'PATCH', body: JSON.stringify(formData) })
        showToast('Connection updated.')
      } else {
        await apiFetch('/api/sso/idps', { method: 'POST', body: JSON.stringify(formData) })
        showToast('Connection created.')
      }
      setSelectedProv(null)
      setEditingIdp(null)
      await fetchIdps()
    } catch (e) {
      showToast('Save failed: ' + e.message, false)
    } finally {
      setSaving(false)
    }
  }, [editingIdp, fetchIdps, showToast])

  const handleDelete = useCallback(async (id) => {
    if (!window.confirm('Remove this IdP connection?')) return
    try {
      await apiFetch(`/api/sso/idps/${id}`, { method: 'DELETE' })
      showToast('Connection removed.')
      await fetchIdps()
    } catch (e) {
      showToast('Delete failed: ' + e.message, false)
    }
  }, [fetchIdps, showToast])

  const handleToggle = useCallback(async (id) => {
    try {
      const data = await apiFetch(`/api/sso/idps/${id}/toggle`, { method: 'POST' })
      setIdps(prev => prev.map(i => i.id === id ? { ...i, active: data.active } : i))
    } catch (e) {
      showToast('Toggle failed: ' + e.message, false)
    }
  }, [showToast])

  const handleTest = useCallback(async (id) => {
    setTestingId(id)
    try {
      const data = await apiFetch(`/api/sso/idps/${id}/test`, { method: 'POST' })
      if (data.ok) {
        showToast('✓ Connection test passed — IdP is reachable.')
      } else {
        showToast('Test failed: ' + (data.error ?? 'unknown error'), false)
      }
      await fetchIdps()
    } catch (e) {
      showToast('Test failed: ' + e.message, false)
    } finally {
      setTestingId(null)
    }
  }, [fetchIdps, showToast])

  const handleEdit = useCallback((idp) => {
    const prov = PROVIDERS.find(p => p.id === idp.vendor_hint) ?? PROVIDERS[5]
    setEditingIdp(idp)
    setSelectedProv(prov)
  }, [])

  const cancelForm = () => { setSelectedProv(null); setEditingIdp(null) }

  const showForm = selectedProv !== null

  return (
    <PageShell title="SSO Configuration" badge="ENTERPRISE SSO" badgeColor="#8b5cf6" subtitle="SAML 2.0 · OIDC · Multi-Provider">
      <div className="max-w-5xl mx-auto space-y-10">

        {/* Header */}
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-white">Single Sign-On Management</h2>
          <p className="text-[12px] text-white/40">
            Configure IdP connections for Okta, Azure AD, Google Workspace, Ping Identity, or any SAML 2.0 / OIDC provider.
            All credentials are stored encrypted server-side. Client secrets are write-only and never returned in API responses.
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
                <h3 className="text-xs font-mono text-white/40 uppercase tracking-widest">Add Provider</h3>
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
            <h3 className="text-xs font-mono text-white/40 uppercase tracking-widest">
              Configured Connections
              {idps.length > 0 && <span className="ml-2 text-white/25">({idps.length})</span>}
            </h3>
            <button
              type="button"
              onClick={fetchIdps}
              className="text-[11px] font-mono border border-white/10 text-white/30 hover:text-white/60 hover:border-white/20 px-2.5 py-1 rounded-xl transition-all"
            >
              ↻ Refresh
            </button>
          </div>

          {loading && (
            <p className="text-[11px] text-white/25 font-mono animate-pulse">Loading…</p>
          )}

          <AnimatePresence>
            {!loading && idps.length === 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="rounded-2xl border border-dashed border-white/10 p-10 text-center"
              >
                <p className="text-white/20 text-[12px]">No IdP connections configured yet.</p>
                <p className="text-white/15 text-[11px] mt-1">Select a provider above to get started.</p>
              </motion.div>
            )}
            {idps.map(idp => (
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
        <div className="rounded-2xl bg-white/[0.02] border border-white/8 px-5 py-4 space-y-2">
          <h4 className="text-[11px] font-mono text-white/35 uppercase">SP Metadata / Callback URLs</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              { label: 'OIDC Callback URL', value: `${window.location.origin}/api/auth/oidc/callback` },
              { label: 'SAML ACS URL', value: `${window.location.origin}/api/auth/saml/acs` },
              { label: 'OIDC Login Initiation', value: `${window.location.origin}/api/auth/oidc/begin?tenant_slug=TENANT&idp_name=NAME` },
              { label: 'SAML Login Initiation', value: `${window.location.origin}/api/auth/saml/begin?tenant_slug=TENANT&idp_name=NAME` },
            ].map(item => (
              <div key={item.label} className="space-y-0.5">
                <p className="text-[9px] font-mono text-white/25 uppercase">{item.label}</p>
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
