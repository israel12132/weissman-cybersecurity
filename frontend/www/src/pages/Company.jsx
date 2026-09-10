import { useTranslation } from 'react-i18next'

export default function Company() {
  const { t } = useTranslation()
  return (
    <div className="mx-auto max-w-3xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('company.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('company.title')}</h1>
      <p className="mt-5 text-lg leading-relaxed text-white/55">{t('company.lead')}</p>
    </div>
  )
}
