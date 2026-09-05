import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import Button from './ui/Button'
import EvidenceNotice from './ui/EvidenceNotice'
import { downloadClientReport } from '../lib/downloadClientReport'

/**
 * Board-grade PDF / Excel chooser for one client. Live API only.
 */
export default function ClientReportDownloadBar({ clientId, className = '' }) {
  const { t, i18n } = useTranslation()
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  if (!clientId) return null

  const run = async (format) => {
    setError('')
    setBusy(format)
    try {
      await downloadClientReport(clientId, format, i18n.language)
    } catch (e) {
      setError(e?.message || t('components.reportView.download_failed'))
    } finally {
      setBusy('')
    }
  }

  return (
    <section
      className={`relative overflow-hidden rounded-2xl border border-cyan-400/30 bg-[#0A1626] p-5 ${className}`}
      data-testid="client-report-download"
    >
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cyan-400 via-teal-500 to-sky-400" />
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-4 min-w-0">
          <img
            src="/logo.svg"
            alt="Weissman Cybersecurity"
            className="h-10 w-auto shrink-0"
          />
          <div className="min-w-0">
            <p className="text-[10px] font-mono uppercase tracking-[0.22em] text-cyan-400/80">
              {t('components.reportView.classification')}
            </p>
            <h3 className="text-white font-semibold text-base leading-tight">
              {t('components.reportView.download_bar_title')}
            </h3>
            <p className="text-white/55 text-xs mt-1 leading-relaxed">
              {t('components.reportView.download_bar_hint')}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 shrink-0">
          <Button
            type="button"
            variant="primary"
            size="md"
            loading={busy === 'pdf'}
            disabled={!!busy}
            onClick={() => run('pdf')}
          >
            {t('components.reportView.download_pdf')}
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="md"
            loading={busy === 'xlsx'}
            disabled={!!busy}
            onClick={() => run('xlsx')}
          >
            {t('components.reportView.download_xlsx')}
          </Button>
        </div>
      </div>
      {error && (
        <p className="mt-3 text-sm text-rose-300" role="alert">
          {error}
        </p>
      )}
      <EvidenceNotice className="mt-4">
        {t('components.reportView.evidence_notice')}
      </EvidenceNotice>
    </section>
  )
}
