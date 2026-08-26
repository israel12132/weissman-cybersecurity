import { useTranslation } from 'react-i18next'
import { Download, RefreshCw, FileSpreadsheet, FileText } from 'lucide-react'
import Button from '../ui/Button'

/**
 * Standard PageShell header actions: reload last engine run + CSV / Excel / PDF export.
 * `onExport` remains the CSV action so existing pages keep compiling.
 */
export default function ShellScanActions({
  onRefresh,
  onExport,
  onExportXlsx,
  onExportPdf,
  refreshLoading = false,
  refreshDisabled = false,
  exportDisabled = false,
  exportLabel,
}) {
  const { t } = useTranslation()
  const csvLabel = exportLabel || t('weissmanFindings.export_csv')
  const showMenu = typeof onExportXlsx === 'function' || typeof onExportPdf === 'function'

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Button variant="unstyled"
        type="button"
        onClick={onRefresh}
        disabled={refreshDisabled || refreshLoading}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border-default)] text-[11px] font-mono text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] disabled:opacity-40"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${refreshLoading ? 'animate-spin' : ''}`} />
        {t('weissmanFindings.refresh')}
      </Button>
      {showMenu ? (
        <div className="inline-flex items-center rounded-lg border border-cyan-500/35 overflow-hidden">
          <Button variant="unstyled"
            type="button"
            onClick={onExport}
            disabled={exportDisabled}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" />
            {csvLabel}
          </Button>
          {typeof onExportXlsx === 'function' && (
            <Button variant="unstyled"
              type="button"
              onClick={onExportXlsx}
              disabled={exportDisabled}
              title={t('weissmanFindings.export_xlsx')}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 border-s border-cyan-500/35 text-[11px] font-mono text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              {t('weissmanFindings.export_xlsx')}
            </Button>
          )}
          {typeof onExportPdf === 'function' && (
            <Button variant="unstyled"
              type="button"
              onClick={onExportPdf}
              disabled={exportDisabled}
              title={t('weissmanFindings.export_pdf')}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 border-s border-cyan-500/35 text-[11px] font-mono text-sky-300 hover:bg-sky-500/10 disabled:opacity-40"
            >
              <FileText className="w-3.5 h-3.5" />
              {t('weissmanFindings.export_pdf')}
            </Button>
          )}
        </div>
      ) : (
        <Button variant="unstyled"
          type="button"
          onClick={onExport}
          disabled={exportDisabled}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
        >
          <Download className="w-3.5 h-3.5" />
          {csvLabel}
        </Button>
      )}
    </div>
  )
}
