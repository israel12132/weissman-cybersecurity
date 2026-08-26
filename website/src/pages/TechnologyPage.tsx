import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { howItWorksIds } from '../content/site'
import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'

const TECH_METRICS = ['productionEngines', 'liveProbes', 'mitreTechniques', 'agentDetections'] as const

export function TechnologyPage() {
  const { t, n } = useI18n()
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">{t('technologyPage.eyebrow')}</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">{t('technologyPage.title')}</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">{t('technologyPage.lead')}</p>
      </header>
      <Section eyebrow={t('technologyPage.stagesEyebrow')} title={t('technologyPage.stagesTitle')}>
        <ol className="space-y-4">
          {howItWorksIds.map((id, i) => (
            <li key={id} className="surface grid gap-4 p-6 md:grid-cols-12">
              <p className="font-mono text-accent md:col-span-2">0{i + 1}</p>
              <div className="md:col-span-10">
                <h2 className="text-2xl text-ink">{t(`howItWorks.${id}.title`)}</h2>
                <p className="mt-2 text-muted">{t(`howItWorks.${id}.body`)}</p>
              </div>
            </li>
          ))}
        </ol>
      </Section>
      <Section eyebrow={t('technologyPage.integrityEyebrow')} title={t('technologyPage.integrityTitle')}>
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {TECH_METRICS.map((key) => (
            <div key={key} className="surface p-5">
              <dt className="text-xs uppercase tracking-[0.14em] text-dim">{t(`metrics.${key}`)}</dt>
              <dd className="mt-2 font-mono text-3xl text-accent" dir="ltr">
                {n(metrics[key].value)}
              </dd>
              <p className="mt-2 font-mono text-[0.65rem] text-dim" dir="ltr">
                {metrics[key].verify}
              </p>
            </div>
          ))}
        </dl>
      </Section>
      <Section>
        <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
      </Section>
    </Layout>
  )
}
