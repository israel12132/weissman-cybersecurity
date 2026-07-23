import { useMemo, useState } from 'react'
import { Download, Search } from 'lucide-react'
import { cn } from '../../lib/cn'
import Input from './Input.jsx'
import Select from './Select.jsx'
import Button from './Button.jsx'
import { exportAuditTrailCsv, exportAuditTrailJson } from '../../lib/exportAuditTrail.js'

/**
 * AuditTrailExport — filter and export the audit trail. Filters by free-text
 * (actor / action / target) and result, then exports the filtered set to CSV or
 * JSON via the shared, injection-safe export helpers.
 *
 * @param {Array<{timestamp,actor,action,target,ip,result,detail}>} entries
 * @param {string} [filenamePrefix='audit-trail']
 */
export default function AuditTrailExport({ entries = [], filenamePrefix = 'audit-trail', className, ...props }) {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState('all')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (Array.isArray(entries) ? entries : []).filter((e) => {
      if (result !== 'all' && String(e?.result).toLowerCase() !== result) return false
      if (!q) return true
      return [e?.actor, e?.action, e?.target].some((v) => String(v ?? '').toLowerCase().includes(q))
    })
  }, [entries, query, result])

  return (
    <div className={cn('flex flex-col gap-3', className)} {...props}>
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[12rem] flex-1">
          <Input
            label="Filter"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="actor, action or target…"
            leftAddon={<Search />}
          />
        </div>
        <div className="w-40">
          <Select
            label="Result"
            value={result}
            onChange={(e) => setResult(e.target.value)}
            options={[
              { value: 'all', label: 'All results' },
              { value: 'success', label: 'Success' },
              { value: 'failure', label: 'Failure' },
            ]}
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs text-text-muted tabular-nums">
          {filtered.length} of {Array.isArray(entries) ? entries.length : 0} entries
        </span>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            leftIcon={<Download />}
            disabled={filtered.length === 0}
            onClick={() => exportAuditTrailCsv(filtered, filenamePrefix)}
          >
            Export CSV
          </Button>
          <Button
            size="sm"
            variant="secondary"
            leftIcon={<Download />}
            disabled={filtered.length === 0}
            onClick={() => exportAuditTrailJson(filtered, filenamePrefix)}
          >
            Export JSON
          </Button>
        </div>
      </div>
    </div>
  )
}

export { AuditTrailExport }
