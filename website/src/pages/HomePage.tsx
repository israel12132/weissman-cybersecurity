import { ButtonLink } from '../components/Button'
import { DemoForm } from '../components/DemoForm'
import { DemoJourney } from '../components/DemoJourney'
import { FeaturedRail } from '../components/FeaturedRail'
import { Hero } from '../components/Hero'
import { InteractiveProduct } from '../components/InteractiveProduct'
import { Layout } from '../components/Layout'
import { MetricCounter } from '../components/MetricCounter'
import { PlatformTabs } from '../components/PlatformTabs'
import { ProcessTimeline } from '../components/ProcessTimeline'
import { ProductScene } from '../components/ProductScene'
import { ResourceGrid } from '../components/ResourceGrid'
import { ScrollStory } from '../components/ScrollStory'
import { Section } from '../components/Section'
import { StickySectionNav } from '../components/StickySectionNav'
import { A } from '../components/A'
import {
  capabilityHrefs,
  capabilityIds,
  proofIds,
  solutionIds,
} from '../content/site'
import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'

const PROOF_METRICS = [
  ['productionEngines', metrics.productionEngines.value],
  ['liveProbes', metrics.liveProbes.value],
  ['mitreTechniques', metrics.mitreTechniques.value],
  ['commandCenterRoutes', metrics.commandCenterRoutes.value],
] as const

export function HomePage() {
  const { t, n } = useI18n()
  const featuredCap = capabilityIds[0]
  const restCaps = capabilityIds.slice(1)
  const leadSolutions = solutionIds.slice(0, 2)
  const restSolutions = solutionIds.slice(2)

  return (
    <Layout>
      <Hero />
      <FeaturedRail />
      <StickySectionNav />

      <Section id="why-us" eyebrow={t('home.threatEyebrow')} title={t('home.threatTitle')} sub={t('home.storySub')}>
        <ScrollStory />
      </Section>

      <Section id="platform" eyebrow={t('home.platformEyebrow')} title={t('home.platformTitle')} sub={t('home.platformSub')}>
        <PlatformTabs />
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <ButtonLink href="#experience" analyticsEvent="platform_cta_click" analyticsPayload={{ placement: 'after_platform' }}>
            {t('cta.experiencePlatform')}
          </ButtonLink>
          <p className="max-w-md text-sm text-muted">{t('home.interactCtaSub')}</p>
        </div>
      </Section>

      <Section
        id="experience"
        eyebrow={t('home.interactiveEyebrow')}
        title={t('home.interactiveTitle')}
        sub={t('home.interactiveSub')}
      >
        <InteractiveProduct />
      </Section>

      <Section id="capabilities" eyebrow={t('home.capabilitiesEyebrow')} title={t('home.capabilitiesTitle')}>
        <div className="grid items-center gap-10 lg:grid-cols-12">
          <div className="lg:col-span-7">
            <ProductScene productId="vulnerability-research" accent="risk" />
            <h3 className="mt-6 text-2xl text-ink">{t(`capabilities.${featuredCap}.title`)}</h3>
            <p className="mt-3 text-muted">{t(`capabilities.${featuredCap}.body`)}</p>
            <A
              className="mt-4 inline-flex min-h-11 items-center text-sm font-semibold text-accent"
              href={capabilityHrefs[featuredCap]}
            >
              {t('cta.learnMore')}
            </A>
          </div>
          <ul className="space-y-3 lg:col-span-5">
            {restCaps.map((id) => (
              <li key={id}>
                <A
                  className="group flex gap-4 rounded-[14px] border border-[var(--line)] p-4 transition duration-base hover:border-accent/40"
                  href={capabilityHrefs[id]}
                >
                  <span className="mt-1 h-8 w-px shrink-0 bg-accent/50 transition duration-swift group-hover:bg-accent" />
                  <span>
                    <span className="block text-ink">{t(`capabilities.${id}.title`)}</span>
                    <span className="mt-1 block text-sm text-muted">{t(`capabilities.${id}.body`)}</span>
                  </span>
                </A>
              </li>
            ))}
          </ul>
        </div>
      </Section>

      <Section id="how-it-works" eyebrow={t('home.howEyebrow')} title={t('home.howTitle')}>
        <ProcessTimeline />
        <div className="mt-10">
          <ButtonLink variant="ghost" href="/technology/">
            {t('cta.technologyWalkthrough')}
          </ButtonLink>
        </div>
      </Section>

      <Section eyebrow={t('home.solutionsEyebrow')} title={t('home.solutionsTitle')}>
        <div className="grid gap-4 lg:grid-cols-2">
          {leadSolutions.map((id, i) => (
            <article
              key={id}
              id={id}
              className={`overflow-hidden rounded-[14px] border border-[var(--line)] ${i === 0 ? 'bg-[radial-gradient(ellipse_at_top_right,rgba(34,211,238,0.12),transparent_55%)]' : 'bg-[radial-gradient(ellipse_at_top_left,rgba(232,184,109,0.1),transparent_55%)]'}`}
            >
              <div className="p-6 md:p-8">
                <p className="font-mono text-[11px] tracking-[0.14em] text-accent">{t('home.solutionsAudience')}</p>
                <h3 className="mt-3 display text-2xl text-ink">{t(`solutions.${id}.title`)}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted">{t(`solutions.${id}.body`)}</p>
                <ul className="mt-5 space-y-2 text-sm text-muted">
                  {[0, 1, 2].map((j) => (
                    <li key={j}>
                      {t(`solutions.${id}.points.${j}`, {
                        routes: n(metrics.commandCenterRoutes.value),
                        probes: n(metrics.liveProbes.value),
                        techniques: n(metrics.mitreTechniques.value),
                      })}
                    </li>
                  ))}
                </ul>
              </div>
            </article>
          ))}
        </div>
        <div className="mt-4 flex snap-x gap-4 overflow-x-auto pb-2">
          {restSolutions.map((id) => (
            <article key={id} id={id} className="surface w-[min(22rem,85vw)] shrink-0 snap-start p-5">
              <h3 className="text-lg text-ink">{t(`solutions.${id}.title`)}</h3>
              <p className="mt-2 text-sm text-muted">{t(`solutions.${id}.body`)}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section id="proof" eyebrow={t('home.proofEyebrow')} title={t('home.proofTitle')} sub={t('home.proofSub')}>
        <dl className="mb-12 grid grid-cols-2 gap-6 lg:grid-cols-4">
          {PROOF_METRICS.map(([key, value]) => (
            <div key={key}>
              <dt className="text-xs tracking-[0.14em] text-dim">{t(`metrics.${key}`)}</dt>
              <dd className="mt-2 font-mono text-4xl text-accent md:text-5xl">
                <MetricCounter value={value} />
              </dd>
            </div>
          ))}
        </dl>
        <div className="divide-y divide-[var(--line)] border-y border-[var(--line)]">
          {proofIds.map((id) => (
            <article key={id} className="grid gap-3 py-6 md:grid-cols-12">
              <h3 className="text-ink md:col-span-4">{t(`proof.${id}.title`)}</h3>
              <p className="text-sm leading-relaxed text-muted md:col-span-8">{t(`proof.${id}.body`)}</p>
            </article>
          ))}
        </div>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <ButtonLink href="#contact" analyticsEvent="demo_cta_click" analyticsPayload={{ placement: 'after_proof' }}>
            {t('cta.seeFit')}
          </ButtonLink>
          <p className="max-w-md text-sm text-muted">{t('home.trustCtaSub')}</p>
        </div>
      </Section>

      <Section id="resources" eyebrow={t('home.resourcesEyebrow')} title={t('home.resourcesTitle')}>
        <ResourceGrid />
      </Section>

      <section
        id="contact"
        className="border-t border-[var(--line)] bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.12),transparent_55%)] py-20 md:py-24"
      >
        <div className="site-wrap grid items-start gap-12 lg:grid-cols-12">
          <div className="lg:col-span-5">
            <p className="eyebrow">{t('home.finalEyebrow')}</p>
            <h2 className="display mt-3 text-4xl text-ink md:text-5xl">{t('home.finalTitle')}</h2>
            <p className="mt-4 text-lg text-muted">{t('home.finalBody')}</p>
            <div className="mt-8">
              <DemoJourney />
            </div>
            <div className="mt-8">
              <ButtonLink variant="ghost" href="/signup.html" analyticsEvent="platform_cta_click" analyticsPayload={{ placement: 'final_trial' }}>
                {t('cta.startTrial')}
              </ButtonLink>
            </div>
          </div>
          <div className="lg:col-span-7">
            <p className="mb-4 text-sm font-medium text-ink">{t('demoJourney.formTitle')}</p>
            <DemoForm />
          </div>
        </div>
      </section>
    </Layout>
  )
}
