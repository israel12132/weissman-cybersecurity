import { ButtonLink } from '../components/Button'
import { FeaturedRail } from '../components/FeaturedRail'
import { Hero } from '../components/Hero'
import { InteractiveProduct } from '../components/InteractiveProduct'
import { Layout } from '../components/Layout'
import { PlatformTabs } from '../components/PlatformTabs'
import { ResourceGrid } from '../components/ResourceGrid'
import { Reveal } from '../components/Reveal'
import { Section } from '../components/Section'
import { StickySectionNav } from '../components/StickySectionNav'
import { A } from '../components/A'
import {
  capabilityHrefs,
  capabilityIds,
  howItWorksIds,
  proofIds,
  solutionIds,
  threatStoryIds,
} from '../content/site'
import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'

export function HomePage() {
  const { t, n } = useI18n()
  return (
    <Layout>
      <Hero />
      <FeaturedRail />
      <StickySectionNav />

      <Section id="why-us" eyebrow={t('home.threatEyebrow')} title={t('home.threatTitle')}>
        <div className="grid gap-4 md:grid-cols-3">
          {threatStoryIds.map((step) => (
            <Reveal key={step}>
              <article className="surface h-full p-6">
                <p className="font-mono text-xs text-accent">{step}</p>
                <h3 className="mt-3 text-xl text-ink">{t(`home.threat.${step}.title`)}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted">{t(`home.threat.${step}.body`)}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="platform" eyebrow={t('home.platformEyebrow')} title={t('home.platformTitle')} sub={t('home.platformSub')}>
        <PlatformTabs />
      </Section>

      <Section eyebrow={t('home.interactiveEyebrow')} title={t('home.interactiveTitle')} sub={t('home.interactiveSub')}>
        <InteractiveProduct />
      </Section>

      <Section id="capabilities" eyebrow={t('home.capabilitiesEyebrow')} title={t('home.capabilitiesTitle')}>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {capabilityIds.map((id) => (
            <Reveal key={id}>
              <A className="surface group block h-full p-6 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={capabilityHrefs[id]}>
                <h3 className="text-lg text-ink">{t(`capabilities.${id}.title`)}</h3>
                <p className="mt-2 text-sm text-muted">{t(`capabilities.${id}.body`)}</p>
                <p className="mt-4 text-sm font-semibold text-accent">
                  {t('cta.learnMore')}{' '}
                  <span className="inline-block transition-transform group-hover:translate-x-0.5 rtl:rotate-180 rtl:group-hover:-translate-x-0.5">→</span>
                </p>
              </A>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="how-it-works" eyebrow={t('home.howEyebrow')} title={t('home.howTitle')}>
        <ol className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {howItWorksIds.map((id, i) => (
            <li key={id} className="surface p-6">
              <p className="font-mono text-xs text-ops">0{i + 1}</p>
              <h3 className="mt-3 text-xl text-ink">{t(`howItWorks.${id}.title`)}</h3>
              <p className="mt-3 text-sm text-muted">{t(`howItWorks.${id}.body`)}</p>
            </li>
          ))}
        </ol>
        <div className="mt-8">
          <ButtonLink variant="ghost" href="/technology/">
            {t('cta.technologyWalkthrough')}
          </ButtonLink>
        </div>
      </Section>

      <Section eyebrow={t('home.solutionsEyebrow')} title={t('home.solutionsTitle')}>
        <div className="grid gap-4 lg:grid-cols-2">
          {solutionIds.map((id) => (
            <article key={id} id={id} className="surface p-6">
              <h3 className="text-xl text-ink">{t(`solutions.${id}.title`)}</h3>
              <p className="mt-2 text-sm text-muted">{t(`solutions.${id}.body`)}</p>
              <ul className="mt-4 space-y-1 text-sm text-muted">
                {[0, 1, 2].map((i) => (
                  <li key={i}>
                    ▸{' '}
                    {t(`solutions.${id}.points.${i}`, {
                      routes: n(metrics.commandCenterRoutes.value),
                      probes: n(metrics.liveProbes.value),
                      techniques: n(metrics.mitreTechniques.value),
                    })}
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </Section>

      <Section id="proof" eyebrow={t('home.proofEyebrow')} title={t('home.proofTitle')} sub={t('home.proofSub')}>
        <div className="grid gap-4 md:grid-cols-2">
          {proofIds.map((id) => (
            <article key={id} className="surface p-6">
              <h3 className="text-lg text-ink">{t(`proof.${id}.title`)}</h3>
              <p className="mt-2 text-sm text-muted">{t(`proof.${id}.body`)}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section id="resources" eyebrow={t('home.resourcesEyebrow')} title={t('home.resourcesTitle')}>
        <ResourceGrid />
      </Section>

      <section id="contact" className="border-t border-[var(--line)] bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.12),transparent_55%)] py-24">
        <div className="site-wrap max-w-3xl text-center">
          <h2 className="display text-4xl text-ink md:text-5xl">{t('home.finalTitle')}</h2>
          <p className="mx-auto mt-4 max-w-xl text-lg text-muted">{t('home.finalBody')}</p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
            <ButtonLink variant="ghost" href="/signup.html">
              {t('cta.startTrial')}
            </ButtonLink>
          </div>
        </div>
      </section>
    </Layout>
  )
}
