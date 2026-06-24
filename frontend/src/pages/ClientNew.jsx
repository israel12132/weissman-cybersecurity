import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ClientOnboardingWizard from '../components/clients/ClientOnboardingWizard'
import { apiFetch } from '../lib/apiBase'

export default function ClientNew() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(payload) {
    setError('')
    setSubmitting(true)
    try {
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

  return (
    <PageShell
      title={t('pages.clientNew.title')}
      subtitle={t('pages.clientOnboarding.subtitle')}
    >
      <div className="max-w-4xl mx-auto space-y-6">
        <EvidenceNotice>{t('pages.clientOnboarding.evidence_notice')}</EvidenceNotice>
        <ClientOnboardingWizard onSubmit={handleSubmit} submitting={submitting} error={error} />
        <div className="text-center">
          <button
            type="button"
            onClick={() => navigate('/clients')}
            className="text-sm text-white/40 hover:text-white/70"
            disabled={submitting}
          >
            {t('pages.clientNew.cancel')}
          </button>
        </div>
      </div>
    </PageShell>
  )
}
