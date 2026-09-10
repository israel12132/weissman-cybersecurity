import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { fetchPlatformPulse } from '../lib/liveApi'

export default function Pricing() {
  const { t } = useTranslation()
  const [count, setCount] = useState(null)
  useEffect(() => {
    fetchPlatformPulse()
      .then((d) => setCount(d.production_engines))
      .catch(() => setCount(null))
  }, [])
  const engines = t('pricing.engines_line', { count: count ?? '—' })
  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('pricing.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('pricing.title')}</h1>
      <p className="mt-4 max-w-2xl text-white/55">{t('pricing.lead')}</p>
      <div className="mt-12 grid gap-4 lg:grid-cols-3">
        <Tier
          name={t('pricing.open')}
          price={t('pricing.open_price')}
          unit={t('pricing.open_unit')}
          items={[engines, t('pricing.open_1'), t('pricing.open_2'), t('pricing.open_3'), t('pricing.open_4')]}
          cta={<Link to="/contact" className="mt-6 block rounded-xl border border-white/15 px-4 py-2.5 text-center text-sm">{t('pricing.open_cta')}</Link>}
        />
        <Tier
          featured
          name={t('pricing.pro')}
          price={t('pricing.pro_price')}
          unit={t('pricing.pro_unit')}
          items={[t('pricing.pro_1'), t('pricing.pro_2'), t('pricing.pro_3'), t('pricing.pro_4')]}
          cta={<Link to="/signup" className="mt-6 block rounded-xl bg-cyan-400 px-4 py-2.5 text-center text-sm font-semibold text-[#041018]">{t('pricing.pro_cta')}</Link>}
        />
        <Tier
          name={t('pricing.ent')}
          price={t('pricing.ent_price')}
          unit=""
          items={[t('pricing.ent_1'), t('pricing.ent_2'), t('pricing.ent_3'), t('pricing.ent_4')]}
          cta={<Link to="/contact" className="mt-6 block rounded-xl border border-white/15 px-4 py-2.5 text-center text-sm">{t('pricing.ent_cta')}</Link>}
        />
      </div>
    </div>
  )
}

function Tier({ name, price, unit, items, cta, featured }) {
  return (
    <div className={`flex flex-col rounded-2xl border p-7 ${featured ? 'border-cyan-400/40 shadow-[0_0_40px_rgba(34,211,238,0.12)]' : 'border-white/10'}`}>
      <h2 className="text-[11px] uppercase tracking-[0.18em] text-cyan-300/80">{name}</h2>
      <div className="mt-3 font-display text-4xl font-semibold">
        {price}
        {unit ? <span className="text-base text-white/40">{unit}</span> : null}
      </div>
      <ul className="mt-6 flex-1 space-y-2 text-sm text-white/55">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      {cta}
    </div>
  )
}
