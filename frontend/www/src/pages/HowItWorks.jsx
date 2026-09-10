import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'

export default function HowItWorks() {
  const { t } = useTranslation()
  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('how.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('how.title')}</h1>
      <p className="mt-4 max-w-2xl text-white/55">{t('how.lead')}</p>
      <div className="mt-12 grid gap-4 lg:grid-cols-4">
        {['1', '2', '3', '4'].map((n) => (
          <div key={n} className="rounded-2xl border border-white/10 p-6">
            <div className="font-mono text-cyan-300">{n.padStart(2, '0')}</div>
            <h2 className="mt-3 font-display text-xl">{t(`steps.${n}.title`)}</h2>
            <p className="mt-2 text-sm text-white/50">{t(`steps.${n}.body`)}</p>
          </div>
        ))}
      </div>
      <Link to="/login" className="mt-12 inline-flex rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-[#041018]">
        {t('home.cta_enter')}
      </Link>
    </div>
  )
}
