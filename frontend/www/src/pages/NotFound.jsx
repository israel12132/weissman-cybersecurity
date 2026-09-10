import { useTranslation } from 'react-i18next'

export default function NotFound() {
  const { t } = useTranslation()
  return (
    <div className="mx-auto max-w-xl px-5 py-24 text-center">
      <h1 className="font-display text-3xl font-semibold">{t('notfound.title')}</h1>
      <p className="mt-3 text-white/50">{t('notfound.lead')}</p>
      <a href="/" className="mt-8 inline-flex text-cyan-300">{t('notfound.home')}</a>
    </div>
  )
}
