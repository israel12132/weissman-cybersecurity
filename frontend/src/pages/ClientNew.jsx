import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EmptyState from '../components/ui/EmptyState'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { apiFetch } from '../lib/apiBase'

export default function ClientNew() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    name: '',
    contact_email: '',
    domains: '',
    ip_ranges: '',
    tech_stack: '',
    auto_detect_tech_stack: true,
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  function handleChange(e) {
    const { name, value, type, checked } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    if (!formData.name.trim()) {
      setError(t('pages.clientNew.name_required'))
      return
    }
    if (!formData.contact_email.trim()) {
      setError(t('pages.clientNew.email_required'))
      return
    }
    if (!formData.domains.trim()) {
      setError(t('pages.clientNew.domain_required'))
      return
    }

    const domains = formData.domains.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean)
    const ip_ranges = formData.ip_ranges.split(/[\n,]+/).map((ip) => ip.trim()).filter(Boolean)
    const tech_stack = formData.tech_stack.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

    if (domains.length === 0) {
      setError(t('pages.clientNew.domain_required'))
      return
    }

    setSubmitting(true)

    try {
      const payload = {
        name: formData.name.trim(),
        contact_email: formData.contact_email.trim(),
        domains: JSON.stringify(domains),
        ip_ranges: JSON.stringify(ip_ranges),
        tech_stack: JSON.stringify(tech_stack),
        auto_detect_tech_stack: formData.auto_detect_tech_stack,
      }

      const response = await apiFetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        let detail = `HTTP ${response.status}`
        try {
          const data = await response.clone().json()
          detail = data.detail || data.error || detail
        } catch {
          try {
            const text = await response.text()
            if (text) detail = text.slice(0, 500)
          } catch { /* ignore */ }
        }
        if (response.status === 403) {
          setError(t('pages.clientNew.error_forbidden', { detail }))
        } else if (response.status === 402) {
          setError(t('pages.clientNew.error_plan_limit', { detail }))
        } else {
          setError(t('pages.clientNew.create_failed', { detail }))
        }
        setSubmitting(false)
        return
      }

      const data = await response.json()
      const clientId = data.id || data.client_id
      navigate(clientId ? `/clients/${clientId}` : '/clients')
    } catch (err) {
      setError(t('pages.clientNew.create_error', { detail: err.message }))
      setSubmitting(false)
    }
  }

  const draftFindings = useMemo(() => {
    const items = []
    const name = formData.name.trim()
    if (name) {
      items.push({
        id: 'draft',
        severity: 'info',
        title: name,
        type: 'client_draft',
        description: formData.contact_email.trim(),
        resource: formData.domains.trim(),
      })
    }
    formData.domains.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean).forEach((domain, i) => {
      items.push({
        id: `domain-${i}`,
        severity: 'info',
        title: domain,
        type: 'domain',
        description: name || 'draft',
        resource: domain,
      })
    })
    formData.ip_ranges.split(/[\n,]+/).map((ip) => ip.trim()).filter(Boolean).forEach((ip, i) => {
      items.push({
        id: `ip-${i}`,
        severity: 'info',
        title: ip,
        type: 'ip_range',
        description: name || 'draft',
        resource: ip,
      })
    })
    formData.tech_stack.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean).forEach((tech, i) => {
      items.push({
        id: `tech-${i}`,
        severity: 'info',
        title: tech,
        type: 'tech_stack',
        description: name || 'draft',
        resource: tech,
      })
    })
    return items
  }, [formData])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(draftFindings, {
    csvPrefix: 'weissman-client-new-draft',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const scopePreviewLines = useMemo(() => {
    const lines = [
      ...formData.domains.split(/[\n,]+/).map((d) => d.trim()).filter(Boolean).map((value, i) => ({ id: `domain-${i}`, label: value, kind: 'domain' })),
      ...formData.ip_ranges.split(/[\n,]+/).map((ip) => ip.trim()).filter(Boolean).map((value, i) => ({ id: `ip-${i}`, label: value, kind: 'ip' })),
      ...formData.tech_stack.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean).map((value, i) => ({ id: `tech-${i}`, label: value, kind: 'tech' })),
    ]
    if (!searchQuery.trim()) return lines
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return lines.filter((line) => ids.has(line.id))
  }, [formData, filteredFindings, searchQuery])

  const resetForm = () => {
    setFormData({
      name: '',
      contact_email: '',
      domains: '',
      ip_ranges: '',
      tech_stack: '',
      auto_detect_tech_stack: true,
    })
    setError('')
  }

  return (
    <PageShell
      title={t('pages.clientNew.title')}
      subtitle={t('pages.clientNew.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={resetForm}
          onExport={exportCsv}
          refreshLoading={submitting}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="max-w-3xl mx-auto space-y-6">
        <EvidenceNotice>{t('pages.clientNew.evidence_notice')}</EvidenceNotice>

        <form onSubmit={handleSubmit} className="space-y-8">
          {error && (
            <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="rounded-xl border border-white/10 bg-black/40 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-white">{t('pages.clientNew.section_basic')}</h3>
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-white/70 mb-2">
                {t('pages.clientNew.client_name')} <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                placeholder={t('pages.clientNew.name_placeholder')}
              />
            </div>
            <div>
              <label htmlFor="contact_email" className="block text-sm font-medium text-white/70 mb-2">
                {t('pages.clientNew.contact_email')} <span className="text-red-400">*</span>
              </label>
              <input
                type="email"
                id="contact_email"
                name="contact_email"
                value={formData.contact_email}
                onChange={handleChange}
                required
                className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                placeholder={t('pages.clientNew.email_placeholder')}
              />
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-black/40 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-white">{t('pages.clientNew.section_scope')}</h3>
            <p className="text-sm text-white/45">{t('pages.clientNew.scope_body')}</p>
            {draftFindings.length > 0 && (
              <>
                <WeissmanListToolbar
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  resultCount={scopePreviewLines.length}
                  totalCount={draftFindings.length}
                />
                {searchQuery.trim() && scopePreviewLines.length === 0 ? (
                  <EmptyState
                    icon="search"
                    title={t('weissmanFindings.filtered_title')}
                    body={t('weissmanFindings.filtered_body')}
                    compact
                  />
                ) : scopePreviewLines.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {scopePreviewLines.map((line) => (
                      <span
                        key={line.id}
                        className="px-2 py-1 rounded-lg border border-white/10 bg-black/50 text-[11px] font-mono text-white/70"
                      >
                        {line.kind}: {line.label}
                      </span>
                    ))}
                  </div>
                ) : null}
              </>
            )}
            <div>
              <label htmlFor="domains" className="block text-sm font-medium text-white/70 mb-2">
                {t('pages.clientNew.authorized_domains')} <span className="text-red-400">*</span>
              </label>
              <textarea
                id="domains"
                name="domains"
                value={formData.domains}
                onChange={handleChange}
                required
                rows={4}
                className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white font-mono text-sm placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                placeholder={t('pages.clientNew.domains_placeholder')}
              />
              <p className="mt-1 text-xs text-white/35">{t('pages.clientNew.domains_hint')}</p>
            </div>
            <div>
              <label htmlFor="ip_ranges" className="block text-sm font-medium text-white/70 mb-2">
                {t('pages.clientNew.authorized_ips')} <span className="text-white/35">({t('pages.clientNew.optional')})</span>
              </label>
              <textarea
                id="ip_ranges"
                name="ip_ranges"
                value={formData.ip_ranges}
                onChange={handleChange}
                rows={3}
                className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white font-mono text-sm placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                placeholder={t('pages.clientNew.ips_placeholder')}
              />
              <p className="mt-1 text-xs text-white/35">{t('pages.clientNew.ips_hint')}</p>
            </div>
          </div>

          <div className="rounded-xl border border-white/10 bg-black/40 p-6 space-y-4">
            <h3 className="text-lg font-semibold text-white">{t('pages.clientNew.tech_stack')}</h3>
            <p className="text-sm text-white/45">{t('pages.clientNew.tech_body')}</p>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                id="auto_detect_tech_stack"
                name="auto_detect_tech_stack"
                checked={formData.auto_detect_tech_stack}
                onChange={handleChange}
                className="w-4 h-4 rounded border-white/20 bg-black/40 text-cyan-500"
              />
              <span className="text-sm text-white/70">{t('pages.clientNew.auto_detect')}</span>
            </label>
            <div>
              <label htmlFor="tech_stack" className="block text-sm font-medium text-white/70 mb-2">
                {t('pages.clientNew.known_tech')} <span className="text-white/35">({t('pages.clientNew.optional')})</span>
              </label>
              <textarea
                id="tech_stack"
                name="tech_stack"
                value={formData.tech_stack}
                onChange={handleChange}
                rows={3}
                className="w-full px-4 py-2 bg-black/50 border border-white/10 rounded-lg text-white font-mono text-sm placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                placeholder={t('pages.clientNew.tech_placeholder')}
              />
              <p className="mt-1 text-xs text-white/35">{t('pages.clientNew.tech_hint')}</p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-6 border-t border-white/10">
            <button
              type="button"
              onClick={() => navigate('/clients')}
              className="px-6 py-2 border border-white/15 text-white/70 rounded-lg hover:bg-white/5 transition-colors"
              disabled={submitting}
            >
              {t('pages.clientNew.cancel')}
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500 disabled:opacity-50 font-medium transition-colors inline-flex items-center gap-2"
            >
              {submitting && (
                <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              )}
              {submitting ? t('pages.clientNew.creating') : t('pages.clientNew.create_client')}
            </button>
          </div>
        </form>
      </div>
    </PageShell>
  )
}
