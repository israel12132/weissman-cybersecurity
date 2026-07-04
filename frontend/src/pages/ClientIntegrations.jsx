import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Cpu,
  KeyRound,
  Link2,
  Save,
  Shield,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../lib/apiBase'
import ClientReadinessBanner from '../components/clients/ClientReadinessBanner'
import { useEngineRequirements, computeLocalReadiness } from '../hooks/useEngineRequirements'

const AGENT_PLATFORMS = ['linux', 'windows', 'macos']
const inputCls =
  'w-full px-3 py-2 bg-black/50 border border-white/10 rounded-lg text-white placeholder-white/30 focus:outline-none focus:border-cyan-500/40 text-sm'
const textareaCls = `${inputCls} font-mono`

function Section({ icon: Icon, title, children }) {
  return (
    <section className="rounded-2xl border border-white/10 bg-gradient-to-b from-white/[0.04] to-black/40 p-5 space-y-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-white">
        <Icon className="w-4 h-4 text-cyan-400" />
        {title}
      </div>
      {children}
    </section>
  )
}

function Field({ label, hint, required, children }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-white/65 mb-1.5 block">
        {label}
        {required && <span className="text-red-400 ms-1">*</span>}
      </span>
      {children}
      {hint && <p className="mt-1 text-[11px] text-white/35">{hint}</p>}
    </label>
  )
}

export default function ClientIntegrations() {
  const { id } = useParams()
  const { t, i18n } = useTranslation()
  const isHe = i18n.language?.startsWith('he')
  const { catalog, tenantStatus } = useEngineRequirements()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [form, setForm] = useState({
    aws_cross_account_role_arn: '',
    aws_external_id: '',
    gcp_project_id: '',
    azure_subscription_id: '',
    azure_tenant_id: '',
    ad_domain: '',
    repo_urls: '',
    agent_platforms: [],
    industrial_ot_enabled: false,
    ip_ranges: '',
    llm_endpoints: [{ url: '', model: '', authorization: '' }],
    engagement_modules: [],
  })

  const patch = (p) => {
    setForm((prev) => ({ ...prev, ...p }))
    setSaved(false)
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch(`/api/clients/${id}/integrations`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      const repos = Array.isArray(d.repo_urls) ? d.repo_urls : []
      const ips = typeof d.ip_ranges === 'string'
        ? (() => { try { return JSON.parse(d.ip_ranges) } catch { return [] } })()
        : []
      const llm = Array.isArray(d.llm_secops_endpoints) && d.llm_secops_endpoints.length
        ? d.llm_secops_endpoints.map((e) => ({
            url: e.url || '',
            model: e.model || '',
            authorization: e.authorization?.configured ? '••••••••' : '',
          }))
        : [{ url: '', model: '', authorization: '' }]
      patch({
        aws_cross_account_role_arn: d.aws_cross_account_role_arn || '',
        aws_external_id: d.aws_external_id?.masked || '',
        gcp_project_id: d.gcp_project_id || '',
        azure_subscription_id: d.azure_subscription_id || '',
        azure_tenant_id: d.azure_tenant_id || '',
        ad_domain: d.ad_domain || '',
        repo_urls: repos.join('\n'),
        agent_platforms: Array.isArray(d.agent_platforms) ? d.agent_platforms : [],
        industrial_ot_enabled: !!d.industrial_ot_enabled,
        ip_ranges: ips.join('\n'),
        llm_endpoints: llm,
        engagement_modules: Array.isArray(d.engagement_modules) ? d.engagement_modules : [],
      })
    } catch (e) {
      setError(e.message || 'Failed to load')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  const readinessForm = useMemo(() => ({
    msa_acknowledged: true,
    emergency_contact_phone: 'ok',
    contact_email: 'ok',
    domains: 'ok',
    ip_ranges: form.ip_ranges,
    aws_cross_account_role_arn: form.aws_cross_account_role_arn,
    aws_external_id: form.aws_external_id.replace(/•/g, 'x'),
    gcp_project_id: form.gcp_project_id,
    azure_subscription_id: form.azure_subscription_id,
    azure_tenant_id: form.azure_tenant_id,
    ad_domain: form.ad_domain,
    repo_urls: form.repo_urls,
    agent_platforms: form.agent_platforms,
    industrial_ot_enabled: form.industrial_ot_enabled,
    llm_secops_urls: form.llm_endpoints?.map((e) => e.url).filter(Boolean).join('\n') || '',
    engagement_modules: form.engagement_modules,
  }), [form])

  const readiness = useMemo(
    () => computeLocalReadiness(catalog, tenantStatus, readinessForm, form.engagement_modules),
    [catalog, tenantStatus, readinessForm, form.engagement_modules],
  )

  async function save() {
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      const repos = form.repo_urls.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      const ips = form.ip_ranges.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      const llm = form.llm_endpoints
        .filter((e) => e.url.trim())
        .map((e) => ({
          url: e.url.trim(),
          model: e.model.trim() || undefined,
          authorization: e.authorization.trim() || undefined,
        }))
      const r = await apiFetch(`/api/clients/${id}/integrations`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          aws_cross_account_role_arn: form.aws_cross_account_role_arn.trim(),
          aws_external_id: form.aws_external_id.trim(),
          gcp_project_id: form.gcp_project_id.trim(),
          azure_subscription_id: form.azure_subscription_id.trim(),
          azure_tenant_id: form.azure_tenant_id.trim(),
          ad_domain: form.ad_domain.trim(),
          repo_urls: repos,
          agent_platforms: form.agent_platforms,
          industrial_ot_enabled: form.industrial_ot_enabled,
          ip_ranges: ips,
          llm_secops_endpoints: llm,
        }),
      })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        throw new Error(d.detail || `HTTP ${r.status}`)
      }
      setSaved(true)
      await load()
    } catch (e) {
      setError(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  function togglePlatform(p) {
    patch({
      agent_platforms: form.agent_platforms.includes(p)
        ? form.agent_platforms.filter((x) => x !== p)
        : [...form.agent_platforms, p],
    })
  }

  const label = (def) => (isHe ? def?.label_he : def?.label_en) || def?.id || ''

  return (
    <PageShell
      title={t('pages.clientIntegrations.title')}
      subtitle={t('pages.clientIntegrations.subtitle')}
      breadcrumbs={[
        { label: t('nav.clients'), to: '/clients' },
        { label: t('pages.clientIntegrations.breadcrumb') },
      ]}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={() => {
            const blob = new Blob([JSON.stringify(form, null, 2)], { type: 'application/json' })
            const a = document.createElement('a')
            a.href = URL.createObjectURL(blob)
            a.download = `client-${id}-integrations.json`
            a.click()
            URL.revokeObjectURL(a.href)
          }}
          refreshLoading={loading}
        />
      )}
    >
      <div className="mb-4 relative max-w-md">
        <input
          type="search"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder={t('pages.clientIntegrations.search_placeholder')}
          className="w-full px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-sm text-white placeholder-white/30"
        />
      </div>
      <ClientReadinessBanner clientId={id} />

      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-950/30 px-4 py-3 text-sm text-red-200 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}
      {saved && (
        <div className="mb-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 px-4 py-3 text-sm text-emerald-200 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          {t('pages.clientIntegrations.saved')}
        </div>
      )}

      {loading ? (
        <p className="text-white/50 text-sm animate-pulse">{t('common.loading')}</p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 space-y-5">
            <Section icon={Cloud} title={t('pages.clientIntegrations.cloud')}>
              <div className="grid sm:grid-cols-2 gap-4">
                <Field label={label(catalog?.requirements?.aws_cross_account)} required>
                  <input className={inputCls} value={form.aws_cross_account_role_arn}
                    onChange={(e) => patch({ aws_cross_account_role_arn: e.target.value })}
                    placeholder="arn:aws:iam::123456789012:role/WeissmanReadOnly" />
                </Field>
                <Field label={t('pages.clientOnboarding.aws_external_id')} required>
                  <input type="password" autoComplete="off" className={inputCls} value={form.aws_external_id}
                    onChange={(e) => patch({ aws_external_id: e.target.value })} placeholder="external-id" />
                </Field>
                <Field label={label(catalog?.requirements?.gcp_project)}>
                  <input className={inputCls} value={form.gcp_project_id} onChange={(e) => patch({ gcp_project_id: e.target.value })} />
                </Field>
                <Field label={t('pages.clientIntegrations.azure_sub')}>
                  <input className={inputCls} value={form.azure_subscription_id} onChange={(e) => patch({ azure_subscription_id: e.target.value })} />
                </Field>
                <Field label={t('pages.clientIntegrations.azure_tenant')}>
                  <input className={inputCls} value={form.azure_tenant_id} onChange={(e) => patch({ azure_tenant_id: e.target.value })} />
                </Field>
              </div>
            </Section>

            <Section icon={Shield} title={t('pages.clientIntegrations.identity')}>
              <Field label={label(catalog?.requirements?.ad_domain)}>
                <input className={inputCls} value={form.ad_domain} onChange={(e) => patch({ ad_domain: e.target.value })} placeholder="corp.example.com" />
              </Field>
            </Section>

            <Section icon={Link2} title={t('pages.clientIntegrations.iac')}>
              <Field label={label(catalog?.requirements?.iac_repos)}>
                <textarea className={textareaCls} rows={3} value={form.repo_urls} onChange={(e) => patch({ repo_urls: e.target.value })} />
              </Field>
            </Section>

            <Section icon={Cpu} title={t('pages.clientIntegrations.agents_ot')}>
              <div className="flex flex-wrap gap-2 mb-3">
                {AGENT_PLATFORMS.map((p) => (
                  <button key={p} type="button" onClick={() => togglePlatform(p)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono border ${
                      form.agent_platforms.includes(p)
                        ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200'
                        : 'border-white/10 text-white/50'
                    }`}>{p}</button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-sm text-white/70 mb-3 cursor-pointer">
                <input type="checkbox" checked={form.industrial_ot_enabled}
                  onChange={(e) => patch({ industrial_ot_enabled: e.target.checked })} />
                {label(catalog?.requirements?.industrial_ot)}
              </label>
              <Field label={label(catalog?.requirements?.scope_ips)}>
                <textarea className={textareaCls} rows={2} value={form.ip_ranges} onChange={(e) => patch({ ip_ranges: e.target.value })} placeholder="10.0.0.0/8" />
              </Field>
              <Link to="/agents" className="text-xs text-cyan-400 hover:text-cyan-300">
                {t('pages.clientIntegrations.open_agents')}
              </Link>
            </Section>

            <Section icon={KeyRound} title={t('pages.clientIntegrations.llm_client')}>
              {form.llm_endpoints.map((ep, i) => (
                <div key={i} className="grid sm:grid-cols-3 gap-2 mb-2 p-3 rounded-xl border border-white/5 bg-black/30">
                  <input className={inputCls} placeholder="https://api.example.com/v1/chat" value={ep.url}
                    onChange={(e) => {
                      const next = [...form.llm_endpoints]
                      next[i] = { ...next[i], url: e.target.value }
                      patch({ llm_endpoints: next })
                    }} />
                  <input className={inputCls} placeholder="model" value={ep.model}
                    onChange={(e) => {
                      const next = [...form.llm_endpoints]
                      next[i] = { ...next[i], model: e.target.value }
                      patch({ llm_endpoints: next })
                    }} />
                  <input type="password" autoComplete="off" className={inputCls} placeholder="Bearer sk-…" value={ep.authorization}
                    onChange={(e) => {
                      const next = [...form.llm_endpoints]
                      next[i] = { ...next[i], authorization: e.target.value }
                      patch({ llm_endpoints: next })
                    }} />
                </div>
              ))}
              <button type="button" className="text-xs text-cyan-400" onClick={() => patch({
                llm_endpoints: [...form.llm_endpoints, { url: '', model: '', authorization: '' }],
              })}>
                + {t('pages.clientIntegrations.add_endpoint')}
              </button>
            </Section>

            <button type="button" disabled={saving} onClick={save}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm">
              <Save className="w-4 h-4" />
              {saving ? t('common.saving') : t('common.save')}
            </button>
          </div>

          <aside className="space-y-4">
            <div className="rounded-2xl border border-white/10 bg-black/40 p-4">
              <h3 className="text-xs font-mono uppercase text-white/40 mb-3">{t('pages.clientOnboarding.readiness')}</h3>
              <div className="text-2xl font-bold text-white mb-1">{readiness.percent}%</div>
              <div className="h-1.5 rounded-full bg-white/10 mb-4 overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all" style={{ width: `${readiness.percent}%` }} />
              </div>
              <ul className="space-y-2 text-xs">
                {readiness.items.filter((i) => i.hard).map((item) => (
                  <li key={item.id} className={`flex gap-2 ${item.satisfied ? 'text-white/55' : 'text-amber-200/90'}`}>
                    {item.satisfied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> : <AlertTriangle className="w-3.5 h-3.5 shrink-0" />}
                    {label(item.def)}
                  </li>
                ))}
              </ul>
            </div>
            {tenantStatus && (
              <div className="rounded-2xl border border-white/10 bg-black/40 p-4 text-xs space-y-2">
                <div className="font-mono uppercase text-white/40">{t('pages.clientOnboarding.tenant_status')}</div>
                <div className="flex justify-between"><span>LLM</span><span className={tenantStatus.llm_configured ? 'text-emerald-400' : 'text-amber-400'}>{tenantStatus.llm_configured ? '✓' : '—'}</span></div>
                <div className="flex justify-between"><span>OAST</span><span className={tenantStatus.oast_configured ? 'text-emerald-400' : 'text-amber-400'}>{tenantStatus.oast_configured ? '✓' : '—'}</span></div>
                <div className="flex justify-between"><span>AI entitlement</span><span className={tenantStatus.ai_heavy_entitled !== false ? 'text-emerald-400' : 'text-amber-400'}>{tenantStatus.ai_heavy_entitled !== false ? '✓' : '—'}</span></div>
                <Link to="/system-core" className="block text-cyan-400 mt-2">{t('pages.clientIntegrations.tenant_settings')}</Link>
              </div>
            )}
            <Link to={`/clients/${id}`} className="block text-center text-xs text-white/45 hover:text-white/70">
              ← {t('pages.clientIntegrations.back_client')}
            </Link>
          </aside>
        </div>
      )}
    </PageShell>
  )
}
