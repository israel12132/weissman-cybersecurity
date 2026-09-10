import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { Ltr } from '../components/Ltr'
import { company } from '../content/site'
import { useI18n } from '../i18n'

export function AboutPage() {
  const { t } = useI18n()
  const roles = Object.keys(company.emails) as Array<keyof typeof company.emails>
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">{t('aboutPage.eyebrow')}</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">{t('brand.legalName')}</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">{t('aboutPage.lede')}</p>
      </header>
      <Section title={t('aboutPage.operateTitle')}>
        <ul className="max-w-3xl space-y-4 text-muted">
          {[0, 1, 2].map((i) => (
            <li key={i} className="surface p-5">
              {t(`aboutPage.points.${i}`)}
            </li>
          ))}
        </ul>
      </Section>
      <Section title={t('aboutPage.contactTitle')}>
        <dl className="grid gap-4 sm:grid-cols-2">
          {roles.map((k) => (
            <div key={k} className="surface p-5">
              <dt className="text-xs uppercase tracking-[0.14em] text-dim">{t(`aboutPage.roles.${k}`)}</dt>
              <dd className="mt-2">
                <a className="text-accent" href={`mailto:${company.emails[k]}`}>
                  <Ltr>{company.emails[k]}</Ltr>
                </a>
              </dd>
            </div>
          ))}
        </dl>
        <p className="mt-8 text-sm text-dim">
          {t('aboutPage.registered', { location: t('brand.location'), id: company.companyIdIsrael })}
        </p>
      </Section>
    </Layout>
  )
}
