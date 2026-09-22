import { useTranslation } from 'react-i18next'
import { Download, RefreshCw, Play } from 'lucide-react'
import Button from '../ui/Button'

/**
 * Standard PageShell header actions: optional Run (launch scan) + reload last
 * engine run + export CSV/XLSX. The Run button only renders when `onRun` is
 * provided, so pages that don't launch scans are unaffected.
 */
export default function ShellScanActions({
  onRefresh,
  onExport,
  onExportXlsx,
  onRun,
  running = false,
  runDisabled = false,
  runLabel,
  refreshLoading = false,
  refreshDisabled = false,
  exportDisabled = false,
  exportXlsxDisabled = false,
  // Defaults to the CSV label; pass an explicit label (e.g. "Export JSON") on
  // pages whose onExport produces a non-CSV file so the toolbar isn't mislabeled.
  exportLabel,
  xlsxLabel,
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {typeof onRun === 'function' && (
        <Button variant="unstyled"
          type="button"
          onClick={onRun}
          disabled={runDisabled || running}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-violet-500/40 text-[11px] font-mono text-violet-200 hover:bg-violet-500/10 disabled:opacity-40"
        >
          <Play className={`w-3.5 h-3.5 ${running ? 'animate-pulse' : ''}`} />
          {running ? t('common.running') : (runLabel || t('common.run'))}
        </Button>
      )}
      <Button variant="unstyled"
        type="button"
        onClick={onRefresh}
        disabled={refreshDisabled || refreshLoading}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border-default)] text-[11px] font-mono text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] disabled:opacity-40"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${refreshLoading ? 'animate-spin' : ''}`} />
        {t('weissmanFindings.refresh')}
      </Button>
      {onExportXlsx && (
        <Button variant="unstyled"
          type="button"
          onClick={onExportXlsx}
          disabled={exportXlsxDisabled}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/35 text-[11px] font-mono text-[var(--severity-low)] hover:bg-emerald-500/10 disabled:opacity-40"
        >
          <Download className="w-3.5 h-3.5" />
          {xlsxLabel || t('common.export_xlsx')}
        </Button>
      )}
      {typeof onExport === 'function' && (
      <Button variant="unstyled"
        type="button"
        onClick={onExport}
        disabled={exportDisabled}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-[var(--text-accent)] hover:bg-cyan-500/10 disabled:opacity-40"
      >
        <Download className="w-3.5 h-3.5" />
        {exportLabel || t('weissmanFindings.export_csv')}
      </Button>
      )}
    </div>
  )
}
