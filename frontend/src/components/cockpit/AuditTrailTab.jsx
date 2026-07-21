import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import { apiFetch } from '../../lib/apiBase'
import DataTable from '../ui/DataTable'

const NS = 'components.cockpitTabs.auditTrail'
const columnHelper = createColumnHelper()

export default function AuditTrailTab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [err, setErr] = useState(null)
  const [loading, setLoading] = useState(true)

  const columns = useMemo(
    () => [
      columnHelper.accessor('timestamp', {
        header: t(`${NS}.colTime`),
        cell: (info) => (
          <span className="text-white/70 whitespace-nowrap">{info.getValue() || '—'}</span>
        ),
      }),
      columnHelper.accessor((r) => sanitizeFindingPlainText(r.user, 500), {
        id: 'user',
        header: t(`${NS}.colUser`),
        cell: (info) => (
          <span className="text-[#22d3ee]/90 max-w-[140px] truncate block" title={info.getValue()}>
            {info.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((r) => (r.user_id != null ? String(r.user_id) : '—'), {
        id: 'user_id',
        header: t(`${NS}.colUserId`),
        cell: (info) => (
          <span className="text-white/50 whitespace-nowrap tabular-nums">{info.getValue()}</span>
        ),
      }),
      columnHelper.accessor((r) => sanitizeFindingPlainText(r.action_type, 200), {
        id: 'action_type',
        header: t(`${NS}.colAction`),
        cell: (info) => (
          <span className="text-amber-200/90 whitespace-nowrap">{info.getValue() || '—'}</span>
        ),
      }),
      columnHelper.accessor((r) => sanitizeFindingPlainText(r.ip_address, 80), {
        id: 'ip_address',
        header: t(`${NS}.colIp`),
        cell: (info) => <span className="text-white/50">{info.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((r) => sanitizeFindingPlainText(r.details, 8000), {
        id: 'details',
        header: t(`${NS}.colDetails`),
        cell: (info) => (
          <span className="text-white/60 max-w-md break-words block">{info.getValue() || '—'}</span>
        ),
      }),
    ],
    [t],
  )

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setErr(null)
      try {
        const r = await apiFetch('/api/audit-logs')
        if (cancelled) return
        if (!r.ok) {
          setRows([])
          setErr(await formatApiErrorResponse(r))
          return
        }
        const data = await r.json()
        if (!Array.isArray(data)) {
          setRows([])
          setErr(t(`${NS}.unexpectedResponse`))
          return
        }
        setRows(data)
      } catch (e) {
        if (!cancelled) {
          setRows([])
          setErr(e?.message || t(`${NS}.loadFailed`))
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [t])

  return (
    <div className="p-6 text-white/90 max-w-6xl mx-auto">
      <h2 className="text-lg font-semibold mb-1 tracking-tight text-white">{t(`${NS}.title`)}</h2>
      <p className="text-xs text-white/50 mb-6 uppercase tracking-widest">
        {t(`${NS}.subtitle`)}
      </p>
      {loading && <p className="text-sm text-white/40">{t(`${NS}.loading`)}</p>}
      {err && (
        <div className="text-sm text-red-300 mb-4 rounded-lg border border-red-500/40 bg-red-950/30 px-4 py-3" role="alert">
          {err}
        </div>
      )}
      {!loading && !err && (
        <DataTable
          id="audit-trail-table"
          columns={columns}
          data={rows}
          getRowId={(r) => r.id}
          animateRows={false}
          emptyState={<span className="text-white/40">{t(`${NS}.noEntries`)}</span>}
        />
      )}
    </div>
  )
}
