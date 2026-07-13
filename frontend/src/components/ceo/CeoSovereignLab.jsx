import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../lib/apiBase'
import Button from '../ui/Button'

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
      const r = await apiFetch('/api/ceo/sovereign/buffer?limit=200')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
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

  const trigger = async (bufferId) => {
    setBusyId(bufferId)
    setToast('')
    try {
      const r = await apiFetch('/api/ceo/sovereign/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          buffer_id: bufferId,
          trace: 'ceo-sovereign-shadow-preflight',
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setToast(t('components.ceo.sovereignLab.enqueuedJob', { jobId: d.job_id || '' }))
      await load()
    } catch (e) {
      setToast(e.message || t('components.ceo.sovereignLab.enqueueFailed'))
    } finally {
      setBusyId(null)
    }
  }

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
      <div className="overflow-x-auto max-h-[min(480px,55vh)] overflow-y-auto">
        <table className="w-full text-left text-xs font-mono text-[var(--text-secondary)]">
          <thead className="sticky top-0 bg-[var(--bg-0)]/95 border-b border-white/10 text-[10px] uppercase text-[var(--text-muted)]">
            <tr>
              <th className="p-2 pl-4">{t('components.ceo.sovereignLab.colId')}</th>
              <th className="p-2">{t('components.ceo.sovereignLab.colTargetFp')}</th>
              <th className="p-2">{t('components.ceo.sovereignLab.colStatus')}</th>
              <th className="p-2">{t('components.ceo.sovereignLab.colUpdated')}</th>
              <th className="p-2 pr-4">{t('components.ceo.sovereignLab.colAction')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-white/5">
                <td className="p-2 pl-4 text-violet-300">{row.id}</td>
                <td className="p-2 max-w-[200px] truncate" title={row.target_fingerprint}>
                  {row.target_fingerprint}
                </td>
                <td className="p-2">{row.status}</td>
                <td className="p-2 text-[var(--text-muted)]">{row.updated_at}</td>
                <td className="p-2 pr-4">
                  <Button variant="unstyled"
                    type="button"
                    disabled={busyId === row.id}
                    onClick={() => trigger(row.id)}
                    className="text-[10px] font-mono uppercase px-2 py-1 rounded bg-violet-900/60 border border-violet-400/35 text-violet-100 disabled:opacity-40"
                  >
                    {busyId === row.id ? '…' : t('components.ceo.sovereignLab.triggerPreflight')}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
