import { useCallback, useEffect, useMemo, useState } from 'react'
import { apiFetch } from '../lib/apiBase'

const DEFAULT_MODULES = ['baseline_asm']

export function useEngineRequirements() {
  const [catalog, setCatalog] = useState(null)
  const [tenantStatus, setTenantStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [reqR, tenR] = await Promise.all([
        apiFetch('/api/engines/requirements'),
        apiFetch('/api/onboarding/tenant-status'),
      ])
      if (!reqR.ok) throw new Error(`requirements HTTP ${reqR.status}`)
      if (!tenR.ok) throw new Error(`tenant-status HTTP ${tenR.status}`)
      setCatalog(await reqR.json())
      setTenantStatus(await tenR.json())
    } catch (e) {
      setError(e.message || 'Failed to load requirements')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  return { catalog, tenantStatus, loading, error, refresh }
}

export function computeLocalReadiness(catalog, tenantStatus, form, selectedModules) {
  if (!catalog?.requirements) {
    return { ready: false, percent: 0, items: [] }
  }

  const reqIds = new Set()
  for (const mid of selectedModules) {
    const mod = catalog.modules?.[mid]
    mod?.requirements?.forEach((r) => reqIds.add(r))
  }
  if (reqIds.size === 0) {
    ;['msa_acknowledged', 'emergency_contact', 'contact_email', 'scope_domains'].forEach((r) => reqIds.add(r))
  }

  const domains = form.domains.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const ips = form.ip_ranges.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const repos = form.repo_urls.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const platforms = form.agent_platforms || []

  const checks = {
    msa_acknowledged: form.msa_acknowledged,
    emergency_contact: !!form.emergency_contact_phone.trim(),
    contact_email: !!form.contact_email.trim(),
    scope_domains: domains.length > 0,
    scope_ips: ips.length > 0,
    scope_exclusions: true,
    aws_cross_account: !!form.aws_cross_account_role_arn.trim() && !!form.aws_external_id.trim(),
    gcp_project: !!form.gcp_project_id.trim(),
    azure_subscription: !!form.azure_subscription_id.trim() && !!form.azure_tenant_id.trim(),
    ad_domain: !!form.ad_domain.trim(),
    iac_repos: repos.length > 0,
    endpoint_agent: platforms.length > 0,
    industrial_ot: form.industrial_ot_enabled && ips.length > 0,
    llm_secops_endpoints: (() => {
      const urls = form.llm_secops_urls.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
      return urls.length > 0
    })(),
    tenant_llm: tenantStatus?.llm_configured,
    tenant_oast: tenantStatus?.oast_configured,
    tenant_ai_entitlement: tenantStatus?.ai_heavy_entitled !== false,
  }

  const optional = new Set(['scope_exclusions', 'llm_secops_endpoints'])
  if (!selectedModules.includes('industrial_ot')) optional.add('scope_ips')

  const items = [...reqIds].map((id) => {
    const def = catalog.requirements[id] || {}
    const scope = def.scope || 'client'
    const satisfied = scope === 'tenant' ? !!checks[id] : !!checks[id]
    const hard = !optional.has(id)
    return { id, def, satisfied, hard, scope }
  })

  const required = items.filter((i) => i.hard)
  const satisfiedCount = required.filter((i) => i.satisfied).length
  const total = required.length || 1

  return {
    ready: required.every((i) => i.satisfied),
    percent: Math.round((satisfiedCount * 100) / total),
    satisfied: satisfiedCount,
    total: required.length,
    items,
  }
}

export const ALL_MODULE_IDS = DEFAULT_MODULES

export function defaultOnboardingForm() {
  return {
    name: '',
    contact_email: '',
    emergency_contact_name: '',
    emergency_contact_phone: '',
    msa_acknowledged: false,
    domains: '',
    ip_ranges: '',
    exclusions: '',
    tech_stack: '',
    auto_detect_tech_stack: true,
    aws_cross_account_role_arn: '',
    aws_external_id: '',
    gcp_project_id: '',
    azure_subscription_id: '',
    azure_tenant_id: '',
    ad_domain: '',
    repo_urls: '',
    agent_platforms: [],
    llm_secops_urls: '',
    industrial_ot_enabled: false,
    roe_mode: 'safe_proofs',
    stealth_level: 50,
    engagement_modules: [...DEFAULT_MODULES],
  }
}

export function buildClientPayload(form) {
  const domains = form.domains.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const ip_ranges = form.ip_ranges.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const tech_stack = form.tech_stack.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const exclusions = form.exclusions.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const repo_urls = form.repo_urls.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
  const llm_endpoints = form.llm_secops_urls.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)

  return {
    name: form.name.trim(),
    contact_email: form.contact_email.trim(),
    domains: JSON.stringify(domains),
    ip_ranges: JSON.stringify(ip_ranges),
    tech_stack: JSON.stringify(tech_stack),
    auto_detect_tech_stack: form.auto_detect_tech_stack,
    aws_cross_account_role_arn: form.aws_cross_account_role_arn.trim(),
    aws_external_id: form.aws_external_id.trim(),
    gcp_project_id: form.gcp_project_id.trim(),
    engagement_modules: form.engagement_modules,
    onboarding: {
      msa_acknowledged: form.msa_acknowledged,
      emergency_contact_name: form.emergency_contact_name.trim(),
      emergency_contact_phone: form.emergency_contact_phone.trim(),
      exclusions,
      azure_subscription_id: form.azure_subscription_id.trim(),
      azure_tenant_id: form.azure_tenant_id.trim(),
      ad_domain: form.ad_domain.trim(),
      repo_urls,
      agent_platforms: form.agent_platforms,
      industrial_ot_enabled: form.industrial_ot_enabled,
      roe_mode: form.roe_mode,
      stealth_level: form.stealth_level,
      llm_secops: llm_endpoints.length ? { endpoints: llm_endpoints.map((url) => ({ url })) } : undefined,
    },
  }
}
