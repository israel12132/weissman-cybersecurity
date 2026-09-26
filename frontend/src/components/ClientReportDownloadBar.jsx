import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import Button from './ui/Button'
import { apiFetch } from '../utils/apiFetch'
import {
  downloadClientPdf,
  downloadClientXlsx,
  openClientReportView,
} from '../lib/downloadClientReport'

export default function ClientReportDownloadBar({ clientId, className = '' }) {
  const { t, i18n } = useTranslation()
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState('')

  if (!clientId) return null

  const uiLang = (i18n?.language || 'en').toLowerCase().startsWith('he') ? 'he' : 'en'
  const otherLang = uiLang === 'he' ? 'en' : 'he'
  const viewLabel = t('client_detail.report_view')
  // The cross-language button is deliberately labelled in its TARGET language (a language
  // switch affordance), so the key is chosen by the UI language rather than translated.
  const otherLabel =
    uiLang === 'he' ? t('client_detail.report_view_english') : t('client_detail.report_view_hebrew')
  const boardLabel = t('client_detail.report_board')
  const runningLabel = t('client_detail.report_opening')

  async function run(kind) {
    setError('')
    setBusy(kind)
    try {
      if (kind === 'pdf') await downloadClientPdf(apiFetch, clientId)
      else if (kind === 'xlsx') await downloadClientXlsx(apiFetch, clientId)
      else if (kind === 'view') await openClientReportView(apiFetch, clientId, uiLang, 'technical')
      else if (kind === 'view-other')
        await openClientReportView(apiFetch, clientId, otherLang, 'technical')
      else if (kind === 'board') await openClientReportView(apiFetch, clientId, uiLang, 'executive')
    } catch (e) {
      setError(e?.message || t('client_detail.export_server_failed'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className={className}>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          onClick={() => run('view')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
        >
          {busy === 'view' ? runningLabel : viewLabel}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          // Labelled in its TARGET language, so isolate its bidi direction from the surrounding UI
          // (otherwise "View report (EN)" renders as "(View report (EN" inside the RTL layout).
          dir={otherLang === 'he' ? 'rtl' : 'ltr'}
          onClick={() => run('view-other')}
          className="px-3 py-2 rounded-xl text-[11px] font-mono border border-cyan-500/20 bg-cyan-500/5 text-cyan-300/80 hover:bg-cyan-500/15 disabled:opacity-50"
        >
          {busy === 'view-other' ? runningLabel : otherLabel}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          onClick={() => run('board')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-teal-500/40 bg-teal-500/10 text-teal-200 hover:bg-teal-500/20 disabled:opacity-50"
        >
          {busy === 'board' ? runningLabel : boardLabel}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          onClick={() => run('pdf')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 disabled:opacity-50"
        >
          {busy === 'pdf'
            ? t('client_detail.export_server_running')
            : t('client_detail.download_pdf')}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          onClick={() => run('xlsx')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-emerald-500/40 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
        >
          {busy === 'xlsx'
            ? t('client_detail.export_server_running')
            : t('client_detail.download_xlsx')}
        </Button>
      </div>
      {error && (
        <p className="mt-2 text-xs text-rose-300 font-mono" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}
