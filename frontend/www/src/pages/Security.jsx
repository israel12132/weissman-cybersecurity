import { useTranslation } from 'react-i18next'

const LINKS = [
  { href: '/status', key: 'security.status' },
  { href: '/terms.html', key: 'security.terms' },
  { href: '/privacy.html', key: 'security.privacy' },
  { href: '/dpa.html', key: 'security.dpa' },
  { href: '/subprocessors.html', key: 'security.sub' },
  { href: '/security-policy.html', key: 'security.disc' },
  { href: '/.well-known/security.txt', key: 'security.sectxt' },
]

export default function Security() {
  const { t } = useTranslation()
  return (
    <div className="mx-auto max-w-6xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('security.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('security.title')}</h1>
      <p className="mt-4 max-w-2xl text-white/55">{t('security.lead')}</p>
      <ul className="mt-10 grid gap-3 sm:grid-cols-2">
        {LINKS.map((l) => (
          <li key={l.href}>
            <a href={l.href} className="block rounded-xl border border-white/10 px-5 py-4 text-sm hover:border-cyan-400/30">
              {t(l.key)}
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}
