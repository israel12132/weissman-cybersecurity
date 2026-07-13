import { useTranslation } from 'react-i18next'
import { Download, RefreshCw } from 'lucide-react'
import Button from '../ui/Button'

/**
 * Standard PageShell header actions: reload last engine run + export CSV.
 */
export default function ShellScanActions({
  onRefresh,
  onExport,
  refreshLoading = false,
  refreshDisabled = false,
  exportDisabled = false,
}) {
  const { t } = useTranslation()
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
      <Button variant="unstyled"
        type="button"
        onClick={onExport}
        disabled={exportDisabled}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
      >
        <Download className="w-3.5 h-3.5" />
        {t('weissmanFindings.export_csv')}
      </Button>
    </div>
  )
}
