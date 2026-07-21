import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'
import DataTable from '../ui/DataTable'

const columnHelper = createColumnHelper()
const NS = 'components.ceo.sovereignLab'

export default function CeoSovereignLab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [toast, setToast] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const d = await apiFetch('/api/ceo/sovereign/buffer?limit=200')
      setRows(Array.isArray(d) ? d : [])
    } catch (e) {
      setErr(e.message || t('components.ceo.sovereignLab.loadFailed'))
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const trigger = useCallback(
    async (bufferId) => {
      setBusyId(bufferId)
      setToast('')
      try {
        const d = await apiFetch('/api/ceo/sovereign/trigger', {
          method: 'POST',
          body: {
            buffer_id: bufferId,
            trace: 'ceo-sovereign-shadow-preflight',
          },
        })
        setToast(t(`${NS}.enqueuedJob`, { jobId: d.job_id || '' }))
        await load()
      } catch (e) {
        setToast(e.message || t(`${NS}.enqueueFailed`))
      } finally {
        setBusyId(null)
      }
    },
    [t, load],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor('id', {
        header: t(`${NS}.colId`),
        cell: (info) => <span className="text-violet-300">{info.getValue()}</span>,
      }),
      columnHelper.accessor('target_fingerprint', {
        header: t(`${NS}.colTargetFp`),
        cell: (info) => (
          <span className="max-w-[200px] truncate block" title={info.getValue()}>
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor('status', { header: t(`${NS}.colStatus`) }),
      columnHelper.accessor('updated_at', {
        header: t(`${NS}.colUpdated`),
        cell: (info) => <span className="text-[var(--text-muted)]">{info.getValue()}</span>,
      }),
      columnHelper.display({
        id: 'action',
        header: t(`${NS}.colAction`),
        cell: ({ row }) => (
          <Button
            variant="unstyled"
            type="button"
            disabled={busyId === row.original.id}
            onClick={() => trigger(row.original.id)}
            className="text-[10px] font-mono uppercase px-2 py-1 rounded bg-violet-900/60 border border-violet-400/35 text-violet-100 disabled:opacity-40"
          >
            {busyId === row.original.id ? '…' : t(`${NS}.triggerPreflight`)}
          </Button>
        ),
      }),
    ],
    [t, busyId, trigger],
  )

  return (
    <div className="rounded-lg border border-violet-500/25 bg-violet-950/10 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex justify-between items-center flex-wrap gap-2">
        <div>
          <h2 className="text-sm font-semibold text-violet-100 uppercase tracking-widest">
            {t('components.ceo.sovereignLab.title')}
          </h2>
          <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
            {t('components.ceo.sovereignLab.subtitle')}
          </p>
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={load}
          className="text-xs font-mono px-3 py-1.5 rounded border border-violet-400/30 text-violet-200 hover:bg-violet-950/50"
        >
          {t('components.ceo.sovereignLab.refresh')}
        </Button>
      </div>
      {toast && (
        <div className="px-4 py-2 text-[11px] font-mono text-[var(--text-secondary)] border-b border-white/10 bg-black/30">
          {toast}
        </div>
      )}
      {loading && (
        <p className="p-4 text-xs text-[var(--text-muted)] font-mono">{t('components.ceo.sovereignLab.loading')}</p>
      )}
      {err && <p className="p-4 text-xs text-red-400 font-mono">{err}</p>}
      {!loading && !err && (
        <DataTable
          id="ceo-sovereign-lab-table"
          columns={columns}
          data={rows}
          getRowId={(r) => r.id}
          animateRows={false}
        />
      )}
    </div>
  )
}
