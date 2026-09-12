import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import Button from './ui/Button'
import { apiFetch } from '../utils/apiFetch'
import { downloadClientPdf, downloadClientXlsx } from '../lib/downloadClientReport'

export default function ClientReportDownloadBar({ clientId, className = '' }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState('')

  if (!clientId) return null

  async function run(kind) {
    setError('')
    setBusy(kind)
    try {
      if (kind === 'pdf') await downloadClientPdf(apiFetch, clientId)
      else await downloadClientXlsx(apiFetch, clientId)
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
          onClick={() => run('pdf')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-rose-500/40 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20 disabled:opacity-50"
        >
          {busy === 'pdf' ? t('client_detail.export_server_running') : t('client_detail.download_pdf')}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          disabled={!!busy}
          onClick={() => run('xlsx')}
          className="px-4 py-2 rounded-xl text-[11px] font-mono border border-emerald-500/40 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
        >
          {busy === 'xlsx' ? t('client_detail.export_server_running') : t('client_detail.download_xlsx')}
        </Button>
      </div>
      {error && (
        <p className="mt-2 text-xs text-rose-300 font-mono" role="alert">{error}</p>
      )}
    </div>
  )
}
