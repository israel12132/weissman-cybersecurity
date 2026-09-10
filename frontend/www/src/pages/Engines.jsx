import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchEngineCatalog } from '../lib/liveApi'

export default function Engines() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [error, setError] = useState(false)
  const [q, setQ] = useState('')

  useEffect(() => {
    let cancelled = false
    fetchEngineCatalog()
      .then((d) => {
        if (!cancelled) setData(d)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const filtered = useMemo(() => {
    const list = data?.engines || []
    const needle = q.trim().toLowerCase()
    if (!needle) return list
    return list.filter((e) => e.id.toLowerCase().includes(needle) || e.kind.includes(needle))
  }, [data, q])

  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('enginesPage.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('enginesPage.title')}</h1>
      <p className="mt-4 max-w-2xl text-white/55">{t('enginesPage.lead')}</p>
      {error && <p className="mt-8 text-amber-200/90" role="status">{t('enginesPage.unavailable')}</p>}
      {data && (
        <>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <input
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={t('enginesPage.search')}
              className="w-full max-w-md rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm outline-none focus:border-cyan-400/40"
            />
            <p className="text-sm text-white/40">{t('enginesPage.count', { count: filtered.length })}</p>
          </div>
          <ul className="mt-8 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {filtered.map((e) => (
              <li key={e.id} className="rounded-xl border border-white/10 px-4 py-3">
                <div className="font-mono text-sm text-cyan-100">{e.id}</div>
                <div className="mt-1 text-[11px] uppercase tracking-wide text-white/40">
                  {e.category ? `${e.category} · ` : ''}
                  {t(`enginesPage.kind_${e.kind}`, { defaultValue: e.kind })}
                </div>
                {Array.isArray(e.mitre) && e.mitre.length > 0 && (
                  <div className="mt-1 font-mono text-[11px] text-white/35" dir="ltr">
                    {e.mitre.slice(0, 3).join(' · ')}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
