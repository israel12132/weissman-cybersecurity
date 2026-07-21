import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'

// Sensitivity tint.
const SEV = {
  critical: 'text-rose-400 border-rose-500/40 bg-rose-950/30',
  elevated: 'text-amber-400 border-amber-500/40 bg-amber-950/30',
  standard: 'text-emerald-400 border-emerald-500/40 bg-emerald-950/30',
}

// Per-group accent for engine badges.
const GROUP = {
  recon: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  web: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  network: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  cloud: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  ot: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  crypto: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  ai: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30',
  apt: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  stealth: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  supply_chain: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  data: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  malware: 'bg-red-500/15 text-red-300 border-red-500/30',
  mobile: 'bg-lime-500/15 text-lime-300 border-lime-500/30',
  social: 'bg-pink-500/15 text-pink-300 border-pink-500/30',
  defense: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
}

function Field({ label, value, mono = true }) {
  if (value === null || value === undefined || value === '' || value === false) return null
  return (
    <div className="flex items-baseline justify-between gap-3 py-1 border-b border-white/5 last:border-0">
      <span className="text-[11px] uppercase tracking-wider text-slate-500">{label}</span>
      <span className={`text-sm text-slate-200 text-right ${mono ? 'font-mono' : ''}`}>{String(value)}</span>
    </div>
  )
}

function ConfidenceBar({ value }) {
  const v = Math.max(0, Math.min(100, Number(value) || 0))
  const color = v >= 80 ? 'bg-emerald-500' : v >= 55 ? 'bg-amber-500' : 'bg-rose-500'
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 rounded-full bg-white/10 overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${v}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-300 tabular-nums w-10 text-right">{v}%</span>
    </div>
  )
}

export default function TargetIntelligence() {
  const { t } = useTranslation()
  const [target, setTarget] = useState('')
  const [enrich, setEnrich] = useState(false)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const analyze = async (e) => {
    if (e && e.preventDefault) e.preventDefault()
    const tgt = target.trim()
    if (!tgt) return
    setLoading(true)
    setError('')
    setData(null)
    try {
      const qs = `target=${encodeURIComponent(tgt)}${enrich ? '&enrich=1' : ''}`
      const d = await apiFetch(`/api/intel/target-profile?${qs}`)
      setData(d)
    } catch (err) {
      setError((err && err.message) || 'request failed')
    } finally {
      setLoading(false)
    }
  }

  const p = data && data.profile
  const sel = data && data.selection
  const prov = p && p.provenance
  const svc = p && p.service

  return (
    <div className="mx-auto max-w-6xl px-4 py-6 text-slate-200">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold tracking-tight text-white flex items-center gap-2">
          <span aria-hidden>🎯</span> {t('targetIntel.title')}
        </h1>
        <p className="text-sm text-slate-400 mt-1">{t('targetIntel.subtitle')}</p>
      </header>

      <form onSubmit={analyze} className="mb-6">
        <div className="flex gap-2">
          <input
            value={target}
            onChange={(ev) => setTarget(ev.target.value)}
            placeholder={t('targetIntel.placeholder')}
            aria-label={t('targetIntel.title')}
            className="flex-1 rounded-lg border border-white/10 bg-slate-900/60 px-3 py-2 text-sm font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="rounded-lg bg-cyan-600 px-5 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? t('targetIntel.analyzing') : t('targetIntel.analyze')}
          </button>
        </div>
        <label className="mt-2 flex items-center gap-2 text-xs text-slate-400 select-none cursor-pointer w-fit">
          <input
            type="checkbox"
            checked={enrich}
            onChange={(ev) => setEnrich(ev.target.checked)}
            aria-label={t('targetIntel.resolveDns')}
            className="accent-cyan-500"
          />
          {t('targetIntel.resolveDns')}
        </label>
      </form>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-300 mb-4">
          {error}
        </div>
      )}

      {data && (
        <div className="grid gap-5 md:grid-cols-2">
          {/* ── Target profile ── */}
          <section className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                {t('targetIntel.profile')}
              </h2>
              <span
                className={`rounded-md border px-2 py-0.5 text-[11px] font-mono uppercase ${SEV[p.sensitivity] || SEV.standard}`}
              >
                {p.sensitivity}
              </span>
            </div>

            <div className="mb-3">
              <div className="text-lg font-semibold text-white">{p.asset_class}</div>
              <div className="text-xs text-slate-400 font-mono break-all">{p.host}</div>
              {data.resolved ? (
                <div className="mt-1 inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> {t('targetIntel.dnsResolved')}
                </div>
              ) : (
                enrich && (
                  <div className="mt-1 inline-flex items-center gap-1 text-[10px] font-mono text-slate-500">
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-600" /> {t('targetIntel.passiveOnly')}
                  </div>
                )
              )}
            </div>

            <div className="mb-3">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
                {t('targetIntel.confidence')}
              </div>
              <ConfidenceBar value={p.confidence} />
            </div>

            <div className="mb-2">
              <Field label={t('targetIntel.fields.scheme')} value={p.scheme} />
              <Field label={t('targetIntel.fields.port')} value={p.port} />
              {svc && <Field label={t('targetIntel.fields.service')} value={`${svc.name} (${svc.kind})`} />}
              <Field label={t('targetIntel.fields.ipFamily')} value={p.ip_family} />
              <Field label={t('targetIntel.fields.private')} value={p.is_private ? t('targetIntel.yes') : null} />
            </div>

            <div className="text-[11px] uppercase tracking-wider text-slate-500 mt-4 mb-1">
              {t('targetIntel.provenance')}
            </div>
            <div className="mb-2">
              <Field label={t('targetIntel.fields.registrableDomain')} value={prov.registrable_domain} />
              <Field label={t('targetIntel.fields.subdomain')} value={prov.subdomain} />
              <Field label={t('targetIntel.fields.publicSuffix')} value={prov.public_suffix} />
              <Field label={t('targetIntel.fields.tldClass')} value={prov.tld_class !== 'Unknown' ? prov.tld_class : null} />
              <Field label={t('targetIntel.fields.hosting')} value={prov.hosting_provider} />
              <Field
                label={t('targetIntel.fields.networkClass')}
                value={prov.network_class !== 'Unknown' ? prov.network_class : null}
              />
              <Field label={t('targetIntel.fields.idn')} value={prov.idn ? t('targetIntel.yes') : null} />
              <Field label={t('targetIntel.fields.homographRisk')} value={prov.homograph_risk ? `⚠ ${t('targetIntel.yes')}` : null} />
              {Array.isArray(prov.resolved_ips) && prov.resolved_ips.length > 0 && (
                <Field label={t('targetIntel.fields.resolvedIps')} value={prov.resolved_ips.join(', ')} />
              )}
            </div>

            {Array.isArray(p.facets) && p.facets.length > 0 && (
              <div className="mt-3">
                <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
                  {t('targetIntel.facets')}
                </div>
                <div className="flex flex-wrap gap-1">
                  {p.facets.map((f) => (
                    <span
                      key={f}
                      className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-mono text-slate-300"
                    >
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {Array.isArray(prov.evidence) && prov.evidence.length > 0 && (
              <div className="mt-3">
                <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
                  {t('targetIntel.evidence')}
                </div>
                <ul className="space-y-0.5">
                  {prov.evidence.map((ev, i) => (
                    <li key={i} className="text-xs text-slate-400 flex gap-1.5">
                      <span className="text-slate-600">›</span>
                      <span>{ev}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>

          {/* ── Engine selection ── */}
          <section className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                {t('targetIntel.engineSelection')}
              </h2>
              <span className="text-xs font-mono text-slate-400">
                {t('targetIntel.focusCount', { focus: sel.focus_count, total: sel.engine_count })}
              </span>
            </div>

            <p className="text-xs text-slate-400 mb-3">{sel.profile_summary}</p>

            <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
              {t('targetIntel.recommendedFocus')}
            </div>
            <div className="flex flex-wrap gap-1 mb-4">
              {(sel.focus || []).slice(0, 24).map((eid) => (
                <span
                  key={eid}
                  className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-mono text-cyan-300"
                >
                  {eid}
                </span>
              ))}
              {(!sel.focus || sel.focus.length === 0) && (
                <span className="text-xs text-slate-500">{t('targetIntel.noFocus')}</span>
              )}
            </div>

            <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
              {t('targetIntel.rankedTop', { n: Math.min(40, (sel.ranked || []).length) })}
            </div>
            <ol className="space-y-1 max-h-[26rem] overflow-y-auto pr-1">
              {(sel.ranked || []).map((c) => (
                <li
                  key={c.engine_id}
                  className="flex items-center gap-2 rounded-md border border-white/5 bg-white/[0.02] px-2 py-1.5"
                >
                  <span
                    className={`w-9 text-center rounded text-[11px] font-mono tabular-nums ${c.score > 0 ? 'text-emerald-400' : c.score < 0 ? 'text-slate-500' : 'text-slate-400'}`}
                  >
                    {c.score > 0 ? `+${c.score}` : c.score}
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="text-sm text-slate-200 font-mono truncate block">
                      {c.recommended && <span className="text-cyan-400" title="recommended">★ </span>}
                      {c.engine_id}
                    </span>
                    <span className="text-[10px] text-slate-500 truncate block">{c.reason}</span>
                  </span>
                  {c.group && (
                    <span
                      className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-mono uppercase ${GROUP[c.group] || 'bg-white/5 text-slate-400 border-white/10'}`}
                    >
                      {c.group}
                    </span>
                  )}
                </li>
              ))}
            </ol>
          </section>
        </div>
      )}

      {!data && !loading && !error && (
        <div className="rounded-xl border border-dashed border-white/10 bg-slate-900/20 px-6 py-12 text-center text-sm text-slate-500">
          {t('targetIntel.emptyState')}
        </div>
      )}
    </div>
  )
}
