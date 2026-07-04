import { useMemo, useState, useId, cloneElement, isValidElement } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Cloud,
  Cpu,
  FileCheck,
  Globe,
  Server,
  Shield,
} from 'lucide-react'
import {
  buildClientPayload,
  computeLocalReadiness,
  defaultOnboardingForm,
  useEngineRequirements,
} from '../../hooks/useEngineRequirements'

const STEPS = ['legal', 'basic', 'scope', 'modules', 'integrations', 'review']
const AGENT_PLATFORMS = ['linux', 'windows', 'macos']

function Field({ label, required, hint, children }) {
  const autoId = useId()
  const fieldId = isValidElement(children) && children.props.id ? children.props.id : autoId
  return (
    <div>
      <label htmlFor={fieldId} className="block text-sm font-medium text-white/70 mb-2">
        {label}
        {required && <span className="text-red-400 ms-1">*</span>}
      </label>
      {isValidElement(children) ? cloneElement(children, { id: fieldId }) : children}
      {hint && <p className="mt-1 text-xs text-white/35">{hint}</p>}
    </div>
  )
}

const inputCls =
  'w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white placeholder-white/30 focus:outline-none focus:border-cyan-500/40'
const textareaCls = `${inputCls} font-mono text-sm`

export default function ClientOnboardingWizard({ onSubmit, submitting, error: externalError, filterQuery = '' }) {
  const { t, i18n } = useTranslation()
  const isHe = i18n.language?.startsWith('he')
  const { catalog, tenantStatus, loading, error: loadError } = useEngineRequirements()
  const [step, setStep] = useState(0)
  const [form, setForm] = useState(defaultOnboardingForm)
  const [localError, setLocalError] = useState('')

  const label = (def) => (isHe ? def?.label_he : def?.label_en) || def?.id || ''
  const hint = (def) => (isHe ? def?.hint_he : def?.hint_en) || ''

  const readiness = useMemo(
    () => computeLocalReadiness(catalog, tenantStatus, form, form.engagement_modules),
    [catalog, tenantStatus, form],
  )

  const activeReqIds = useMemo(() => {
    const ids = new Set()
    for (const mid of form.engagement_modules) {
      catalog?.modules?.[mid]?.requirements?.forEach((r) => ids.add(r))
    }
    return ids
  }, [catalog, form.engagement_modules])

  const needs = {
    aws: activeReqIds.has('aws_cross_account'),
    gcp: activeReqIds.has('gcp_project'),
    azure: activeReqIds.has('azure_subscription'),
    ad: activeReqIds.has('ad_domain'),
    iac: activeReqIds.has('iac_repos'),
    agent: activeReqIds.has('endpoint_agent'),
    ot: activeReqIds.has('industrial_ot'),
    ai: activeReqIds.has('tenant_llm'),
    oast: activeReqIds.has('tenant_oast'),
  }

  function patch(patch) {
    setForm((prev) => ({ ...prev, ...patch }))
  }

  function toggleModule(id) {
    setForm((prev) => {
      const set = new Set(prev.engagement_modules)
      if (set.has(id)) set.delete(id)
      else set.add(id)
      if (set.size === 0) set.add('baseline_asm')
      return { ...prev, engagement_modules: [...set] }
    })
  }

  function togglePlatform(p) {
    setForm((prev) => {
      const set = new Set(prev.agent_platforms)
      if (set.has(p)) set.delete(p)
      else set.add(p)
      return { ...prev, agent_platforms: [...set] }
    })
  }

  function validateStep() {
    if (step === 0 && !form.msa_acknowledged) {
      return t('pages.clientOnboarding.msa_required')
    }
    if (step === 0 && !form.emergency_contact_phone.trim()) {
      return t('pages.clientOnboarding.emergency_required')
    }
    if (step === 1 && !form.name.trim()) return t('pages.clientNew.name_required')
    if (step === 1 && !form.contact_email.trim()) return t('pages.clientNew.email_required')
    if (step === 2 && !form.domains.trim()) return t('pages.clientNew.domain_required')
    if (step === 4) {
      if (needs.aws && (!form.aws_cross_account_role_arn.trim() || !form.aws_external_id.trim())) {
        return t('pages.clientOnboarding.aws_required')
      }
      if (needs.gcp && !form.gcp_project_id.trim()) return t('pages.clientOnboarding.gcp_required')
      if (needs.azure && (!form.azure_subscription_id.trim() || !form.azure_tenant_id.trim())) {
        return t('pages.clientOnboarding.azure_required')
      }
      if (needs.ad && !form.ad_domain.trim()) return t('pages.clientOnboarding.ad_required')
      if (needs.iac && !form.repo_urls.trim()) return t('pages.clientOnboarding.repos_required')
      if (needs.agent && form.agent_platforms.length === 0) {
        return t('pages.clientOnboarding.agent_platform_required')
      }
      if (needs.ot && (!form.industrial_ot_enabled || !form.ip_ranges.trim())) {
        return t('pages.clientOnboarding.ot_required')
      }
    }
    return ''
  }

  async function handleNext() {
    const err = validateStep()
    if (err) {
      setLocalError(err)
      return
    }
    setLocalError('')
    if (step < STEPS.length - 1) setStep((s) => s + 1)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    const err = validateStep()
    if (err) {
      setLocalError(err)
      return
    }
    if (!readiness.ready) {
      setLocalError(t('pages.clientOnboarding.not_ready'))
      return
    }
    setLocalError('')
    await onSubmit(buildClientPayload(form))
  }

  const stepTitle = t(`pages.clientOnboarding.step_${STEPS[step]}`)

  if (loading) {
    return (
      <div className="rounded-xl border border-white/10 bg-black/40 p-8 text-center text-white/50 text-sm">
        {t('pages.clientOnboarding.loading_catalog')}
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {(externalError || localError || loadError) && (
        <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {externalError || localError || loadError}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400/80">
            {t('pages.clientOnboarding.readiness')}
          </div>
          <div className="text-lg font-semibold text-white">{readiness.percent}%</div>
        </div>
        <div className="flex-1 min-w-[120px] max-w-xs h-2 rounded-full bg-white/10 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-600 to-emerald-500 transition-all duration-300"
            style={{ width: `${readiness.percent}%` }}
          />
        </div>
        <div className="text-xs text-white/45">
          {readiness.satisfied}/{readiness.total} {t('pages.clientOnboarding.requirements_met')}
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {STEPS.map((s, i) => {
          const stepLabel = t(`pages.clientOnboarding.step_${s}`)
          const q = filterQuery.trim().toLowerCase()
          if (q && !stepLabel.toLowerCase().includes(q) && !s.includes(q)) return null
          return (
          <button
            key={s}
            type="button"
            onClick={() => setStep(i)}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-mono border transition-colors ${
              i === step
                ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-200'
                : 'border-white/10 text-white/40 hover:text-white/70'
            }`}
          >
            {i + 1}. {stepLabel}
          </button>
          )
        })}
      </div>

      <div className="rounded-xl border border-white/10 bg-black/40 p-6 space-y-5">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          {step === 0 && <FileCheck className="w-5 h-5 text-cyan-400" />}
          {step === 2 && <Globe className="w-5 h-5 text-cyan-400" />}
          {step === 3 && <Cpu className="w-5 h-5 text-cyan-400" />}
          {step === 4 && <Cloud className="w-5 h-5 text-cyan-400" />}
          {step === 5 && <Shield className="w-5 h-5 text-cyan-400" />}
          {stepTitle}
        </h3>

        {step === 0 && (
          <>
            <label className="flex items-start gap-3 cursor-pointer rounded-lg border border-amber-500/30 bg-amber-950/20 p-4">
              <input
                type="checkbox"
                checked={form.msa_acknowledged}
                onChange={(e) => patch({ msa_acknowledged: e.target.checked })}
                className="mt-1 w-4 h-4"
              />
              <span className="text-sm text-white/80">{t('pages.clientOnboarding.msa_ack')}</span>
            </label>
            <Field label={t('pages.clientOnboarding.emergency_name')} required>
              <input
                className={inputCls}
                value={form.emergency_contact_name}
                onChange={(e) => patch({ emergency_contact_name: e.target.value })}
              />
            </Field>
            <Field label={t('pages.clientOnboarding.emergency_phone')} required hint={t('pages.clientOnboarding.emergency_hint')}>
              <input
                className={inputCls}
                value={form.emergency_contact_phone}
                onChange={(e) => patch({ emergency_contact_phone: e.target.value })}
                placeholder="+972-..."
              />
            </Field>
          </>
        )}

        {step === 1 && (
          <>
            <Field label={t('pages.clientNew.client_name')} required>
              <input className={inputCls} value={form.name} onChange={(e) => patch({ name: e.target.value })} />
            </Field>
            <Field label={t('pages.clientNew.contact_email')} required>
              <input type="email" className={inputCls} value={form.contact_email} onChange={(e) => patch({ contact_email: e.target.value })} />
            </Field>
          </>
        )}

        {step === 2 && (
          <>
            <Field label={t('pages.clientNew.authorized_domains')} required hint={t('pages.clientNew.domains_hint')}>
              <textarea className={textareaCls} rows={4} value={form.domains} onChange={(e) => patch({ domains: e.target.value })} />
            </Field>
            <Field label={t('pages.clientNew.authorized_ips')} hint={t('pages.clientNew.ips_hint')}>
              <textarea className={textareaCls} rows={3} value={form.ip_ranges} onChange={(e) => patch({ ip_ranges: e.target.value })} />
            </Field>
            <Field label={t('pages.clientOnboarding.exclusions')} hint={t('pages.clientOnboarding.exclusions_hint')}>
              <textarea className={textareaCls} rows={2} value={form.exclusions} onChange={(e) => patch({ exclusions: e.target.value })} />
            </Field>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={form.auto_detect_tech_stack} onChange={(e) => patch({ auto_detect_tech_stack: e.target.checked })} />
              <span className="text-sm text-white/70">{t('pages.clientNew.auto_detect')}</span>
            </label>
            <Field label={t('pages.clientNew.known_tech')}>
              <textarea className={textareaCls} rows={2} value={form.tech_stack} onChange={(e) => patch({ tech_stack: e.target.value })} />
            </Field>
          </>
        )}

        {step === 3 && catalog?.modules && (
          <>
            <p className="text-sm text-white/45">{t('pages.clientOnboarding.modules_body')}</p>
            <div className="grid sm:grid-cols-2 gap-3">
              {Object.entries(catalog.modules).map(([id, mod]) => {
                const selected = form.engagement_modules.includes(id)
                const modLabel = isHe ? mod.label_he : mod.label_en
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => toggleModule(id)}
                    className={`text-start p-4 rounded-xl border transition-all ${
                      selected
                        ? 'border-cyan-500/40 bg-cyan-500/10 shadow-[0_0_20px_rgba(34,211,238,0.08)]'
                        : 'border-white/10 bg-black/30 hover:border-white/20'
                    }`}
                  >
                    <div className="font-medium text-white text-sm">{modLabel}</div>
                    <div className="text-[11px] text-white/40 mt-1 font-mono">
                      {mod.engine_count} engines · {mod.requirements?.length} reqs
                    </div>
                  </button>
                )
              })}
            </div>
          </>
        )}

        {step === 4 && (
          <>
            {(needs.aws || needs.gcp || needs.azure) && (
              <div className="space-y-4 pb-4 border-b border-white/10">
                <h4 className="text-sm font-semibold text-white/80 flex items-center gap-2">
                  <Cloud className="w-4 h-4" /> {t('pages.clientOnboarding.cloud_section')}
                </h4>
                {needs.aws && (
                  <>
                    <Field label={label(catalog?.requirements?.aws_cross_account)} required>
                      <input className={inputCls} value={form.aws_cross_account_role_arn} onChange={(e) => patch({ aws_cross_account_role_arn: e.target.value })} placeholder="arn:aws:iam::123456789012:role/WeissmanAudit" />
                    </Field>
                    <Field label="AWS External ID" required>
                      <input type="password" autoComplete="off" className={inputCls} value={form.aws_external_id} onChange={(e) => patch({ aws_external_id: e.target.value })} />
                    </Field>
                  </>
                )}
                {needs.gcp && (
                  <Field label={label(catalog?.requirements?.gcp_project)} required>
                    <input className={inputCls} value={form.gcp_project_id} onChange={(e) => patch({ gcp_project_id: e.target.value })} />
                  </Field>
                )}
                {needs.azure && (
                  <>
                    <Field label={label(catalog?.requirements?.azure_subscription)} required>
                      <input className={inputCls} value={form.azure_subscription_id} onChange={(e) => patch({ azure_subscription_id: e.target.value })} placeholder="subscription-id" />
                    </Field>
                    <Field label="Azure Tenant ID" required>
                      <input className={inputCls} value={form.azure_tenant_id} onChange={(e) => patch({ azure_tenant_id: e.target.value })} />
                    </Field>
                  </>
                )}
              </div>
            )}

            {needs.ad && (
              <Field label={label(catalog?.requirements?.ad_domain)} required hint={hint(catalog?.requirements?.ad_domain)}>
                <input className={inputCls} value={form.ad_domain} onChange={(e) => patch({ ad_domain: e.target.value })} placeholder="corp.example.com" />
              </Field>
            )}

            {needs.iac && (
              <Field label={label(catalog?.requirements?.iac_repos)} required hint={hint(catalog?.requirements?.iac_repos)}>
                <textarea className={textareaCls} rows={3} value={form.repo_urls} onChange={(e) => patch({ repo_urls: e.target.value })} placeholder="https://github.com/org/infra.git" />
              </Field>
            )}

            {needs.agent && (
              <div>
                <div className="text-sm font-medium text-white/70 mb-2">{label(catalog?.requirements?.endpoint_agent)} *</div>
                <div className="flex flex-wrap gap-2">
                  {AGENT_PLATFORMS.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => togglePlatform(p)}
                      className={`px-3 py-2 rounded-lg text-xs font-mono border ${
                        form.agent_platforms.includes(p)
                          ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200'
                          : 'border-white/10 text-white/50'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-xs text-white/35">{hint(catalog?.requirements?.endpoint_agent)}</p>
              </div>
            )}

            {needs.ot && (
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={form.industrial_ot_enabled} onChange={(e) => patch({ industrial_ot_enabled: e.target.checked })} />
                <span className="text-sm text-white/70">{label(catalog?.requirements?.industrial_ot)}</span>
              </label>
            )}

            {needs.ai && (
              <Field label={t('pages.clientOnboarding.llm_client_endpoints')} hint={t('pages.clientOnboarding.llm_client_hint')}>
                <textarea className={textareaCls} rows={2} value={form.llm_secops_urls} onChange={(e) => patch({ llm_secops_urls: e.target.value })} />
              </Field>
            )}

            {(needs.ai || needs.oast) && tenantStatus && (
              <div className="rounded-lg border border-white/10 bg-black/30 p-4 space-y-2 text-sm">
                <div className="text-[10px] font-mono uppercase text-white/40">{t('pages.clientOnboarding.tenant_status')}</div>
                <StatusRow ok={tenantStatus.llm_configured} label={label(catalog?.requirements?.tenant_llm)} />
                <StatusRow ok={tenantStatus.oast_configured} label={label(catalog?.requirements?.tenant_oast)} />
                <StatusRow ok={tenantStatus.ai_heavy_entitled !== false} label={label(catalog?.requirements?.tenant_ai_entitlement)} />
                <Link to="/system-core" className="text-xs text-cyan-400 hover:text-cyan-300 mt-2 inline-block">
                  {t('pages.clientOnboarding.configure_tenant')}
                </Link>
              </div>
            )}
          </>
        )}

        {step === 5 && (
          <>
            <div className="grid sm:grid-cols-2 gap-3 text-sm">
              <SummaryItem label={t('pages.clientNew.client_name')} value={form.name} />
              <SummaryItem label={t('pages.clientNew.contact_email')} value={form.contact_email} />
              <SummaryItem label={t('pages.clientNew.authorized_domains')} value={form.domains.split(/[\n,]+/).filter(Boolean).length + ' domains'} />
              <SummaryItem label={t('pages.clientOnboarding.modules')} value={form.engagement_modules.join(', ')} />
            </div>
            <div className="space-y-2 mt-4">
              {readiness.items.filter((i) => i.hard).map((item) => (
                <div key={item.id} className="flex items-center gap-2 text-sm">
                  {item.satisfied ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  )}
                  <span className={item.satisfied ? 'text-white/70' : 'text-amber-200/90'}>
                    {label(item.def)}
                    {item.scope === 'tenant' && (
                      <span className="ms-1 text-[10px] font-mono text-white/30">(tenant)</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
            {!readiness.ready && (
              <p className="text-amber-300/90 text-sm flex items-center gap-2 mt-4">
                <Server className="w-4 h-4" />
                {t('pages.clientOnboarding.complete_missing')}
              </p>
            )}
          </>
        )}
      </div>

      <div className="flex items-center justify-between pt-2">
        <button
          type="button"
          disabled={step === 0 || submitting}
          onClick={() => setStep((s) => Math.max(0, s - 1))}
          className="px-4 py-2 flex items-center gap-1 border border-white/15 text-white/70 rounded-lg hover:bg-white/5 disabled:opacity-40"
        >
          <ChevronLeft className="w-4 h-4" />
          {t('pages.clientOnboarding.back')}
        </button>
        {step < STEPS.length - 1 ? (
          <button
            type="button"
            onClick={handleNext}
            className="px-6 py-2 flex items-center gap-1 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500 font-medium"
          >
            {t('pages.clientOnboarding.next')}
            <ChevronRight className="w-4 h-4" />
          </button>
        ) : (
          <button
            type="submit"
            disabled={submitting || !readiness.ready}
            className="px-6 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-500 disabled:opacity-50 font-medium inline-flex items-center gap-2"
          >
            {submitting && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
            {submitting ? t('pages.clientNew.creating') : t('pages.clientNew.create_client')}
          </button>
        )}
      </div>
    </form>
  )
}

function StatusRow({ ok, label }) {
  return (
    <div className="flex items-center gap-2">
      {ok ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-amber-400" />}
      <span className={ok ? 'text-white/60' : 'text-amber-200/80'}>{label}</span>
    </div>
  )
}

function SummaryItem({ label, value }) {
  return (
    <div className="rounded-lg border border-white/10 bg-black/30 px-3 py-2">
      <div className="text-[10px] font-mono uppercase text-white/35">{label}</div>
      <div className="text-white/80 truncate">{value || '—'}</div>
    </div>
  )
}
