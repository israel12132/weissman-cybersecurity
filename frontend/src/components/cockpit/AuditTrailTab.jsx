import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import { apiFetch } from '../../utils/apiFetch'

const NS = 'components.cockpitTabs.auditTrail'

export default function AuditTrailTab() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [err, setErr] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setErr(null)
      try {
        const data = await apiFetch('/api/audit-logs')
        if (cancelled) return
        if (!Array.isArray(data)) {
          setRows([])
          setErr(t(`${NS}.unexpectedResponse`))
          return
        }
        setRows(data)
      } catch (e) {
        if (!cancelled) {
          setRows([])
          setErr(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || t(`${NS}.loadFailed`)))
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
        <div className="overflow-x-auto rounded-xl border border-white/10 bg-black/30 backdrop-blur-sm">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-white/50 uppercase tracking-wider">
                <th className="p-3 font-medium">{t(`${NS}.colTime`)}</th>
                <th className="p-3 font-medium">{t(`${NS}.colUser`)}</th>
                <th className="p-3 font-medium">{t(`${NS}.colUserId`)}</th>
                <th className="p-3 font-medium">{t(`${NS}.colAction`)}</th>
                <th className="p-3 font-medium">{t(`${NS}.colIp`)}</th>
                <th className="p-3 font-medium">{t(`${NS}.colDetails`)}</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-white/40">
                    {t(`${NS}.noEntries`)}
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-white/5 hover:bg-white/[0.03] font-mono">
                  <td className="p-3 text-white/70 whitespace-nowrap">{r.timestamp || '—'}</td>
                  <td className="p-3 text-[#22d3ee]/90 max-w-[140px] truncate" title={sanitizeFindingPlainText(r.user, 500)}>
                    {sanitizeFindingPlainText(r.user, 500) || '—'}
                  </td>
                  <td className="p-3 text-white/50 whitespace-nowrap tabular-nums">
                    {r.user_id != null ? String(r.user_id) : '—'}
                  </td>
                  <td className="p-3 text-amber-200/90 whitespace-nowrap">{sanitizeFindingPlainText(r.action_type, 200) || '—'}</td>
                  <td className="p-3 text-white/50">{sanitizeFindingPlainText(r.ip_address, 80) || '—'}</td>
                  <td className="p-3 text-white/60 max-w-md break-words">{sanitizeFindingPlainText(r.details, 8000) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
