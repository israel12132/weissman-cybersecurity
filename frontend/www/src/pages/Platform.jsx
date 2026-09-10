import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'

const LAYERS = ['offensive', 'cloud', 'identity', 'ot', 'ai', 'remediation']

export default function Platform() {
  const { t } = useTranslation()
  const { layer } = useParams()
  const active = LAYERS.includes(layer) ? layer : null

  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('platform.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('platform.title')}</h1>
      <p className="mt-4 max-w-2xl text-white/55">{t('platform.lead')}</p>
      <div className="mt-10 grid gap-4 sm:grid-cols-2">
        {LAYERS.map((id) => (
          <article
            key={id}
            className={`rounded-2xl border p-6 ${active === id ? 'border-cyan-400/40 bg-cyan-400/[0.06]' : 'border-white/10 bg-white/[0.03]'}`}
          >
            <h2 className="font-display text-xl">{t(`layers.${id}.title`)}</h2>
            <p className="mt-2 text-sm text-white/50">{t(`layers.${id}.body`)}</p>
            <Link to={`/platform/${id}`} className="mt-4 inline-block text-sm text-cyan-300">
              {id}
            </Link>
          </article>
        ))}
      </div>
      <p className="mt-10 text-sm text-white/40">
        <a href="/login" className="text-cyan-300">{t('platform.open')}</a>
      </p>
    </div>
  )
}
