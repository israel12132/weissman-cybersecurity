import { useState } from 'react'
import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { solutionIds } from '../content/site'
import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'

export function SolutionsPage() {
  const { t, n } = useI18n()
  const [id, setId] = useState<(typeof solutionIds)[number]>(solutionIds[0])
  const vars = {
    routes: n(metrics.commandCenterRoutes.value),
    probes: n(metrics.liveProbes.value),
    techniques: n(metrics.mitreTechniques.value),
  }

  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">{t('solutions.pageEyebrow')}</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">{t('solutions.pageTitle')}</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">{t('solutions.pageLead')}</p>
      </header>
      <Section>
        <div className="grid gap-8 lg:grid-cols-12">
          <div className="flex flex-col gap-2 lg:col-span-4" role="tablist" aria-label={t('a11y.audiences')}>
            {solutionIds.map((sid) => (
              <button
                key={sid}
                type="button"
                role="tab"
                aria-selected={sid === id}
                className={`min-h-11 rounded-[12px] px-4 text-start text-sm ${sid === id ? 'bg-elevated text-ink' : 'text-muted'}`}
                onClick={() => setId(sid)}
              >
                {t(`solutions.${sid}.title`)}
              </button>
            ))}
          </div>
          <article className="surface p-6 lg:col-span-8" role="tabpanel">
            <h2 className="text-2xl text-ink">{t(`solutions.${id}.title`)}</h2>
            <p className="mt-3 text-muted">{t(`solutions.${id}.body`)}</p>
            <ul className="mt-6 space-y-2 text-sm text-muted">
              {[0, 1, 2].map((i) => (
                <li key={i}>▸ {t(`solutions.${id}.points.${i}`, vars)}</li>
              ))}
            </ul>
            <div className="mt-8">
              <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
            </div>
          </article>
        </div>
      </Section>
    </Layout>
  )
}
