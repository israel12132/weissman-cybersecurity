import { Layout } from '../components/Layout'
import { PlatformTabs } from '../components/PlatformTabs'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { A } from '../components/A'
import { AttackTheater } from '../components/AttackTheater'
import { InteractiveProduct } from '../components/InteractiveProduct'
import { ProcessTimeline } from '../components/ProcessTimeline'
import { products } from '../content/products'
import { useI18n } from '../i18n'

export function PlatformPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <header className="relative overflow-hidden border-b border-[var(--line)]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_70%_50%_at_80%_0%,rgba(34,211,238,0.12),transparent_55%)]" />
        <div className="site-wrap relative grid items-center gap-10 py-16 lg:grid-cols-12">
          <div className="lg:col-span-5">
            <p className="eyebrow">{t('platformPage.eyebrow')}</p>
            <h1 className="display mt-3 max-w-4xl text-4xl text-ink md:text-6xl">{t('platformPage.title')}</h1>
            <p className="mt-6 max-w-2xl text-lg text-muted">{t('platformPage.lead')}</p>
            <div className="mt-8 flex flex-wrap gap-3">
              <ButtonLink href="/contact/" analyticsEvent="demo_cta_click" analyticsPayload={{ placement: 'platform' }}>
                {t('cta.bookDemo')}
              </ButtonLink>
              <ButtonLink variant="ghost" href="#experience" analyticsEvent="platform_cta_click" analyticsPayload={{ placement: 'platform' }}>
                {t('cta.experiencePlatform')}
              </ButtonLink>
            </div>
          </div>
          <div className="lg:col-span-7">
            <AttackTheater />
          </div>
        </div>
      </header>
      <Section eyebrow={t('platformPage.modulesEyebrow')} title={t('platformPage.modulesTitle')}>
        <PlatformTabs />
      </Section>
      <Section id="experience" eyebrow={t('home.interactiveEyebrow')} title={t('home.interactiveTitle')} sub={t('home.interactiveSub')}>
        <InteractiveProduct />
      </Section>
      <Section eyebrow={t('platformPage.indexEyebrow')} title={t('platformPage.indexTitle')}>
        <ul className="grid gap-3 md:grid-cols-2">
          {products.map((p) => (
            <li key={p.id}>
              <A className="group block overflow-hidden rounded-[14px] border border-[var(--line)] transition duration-base hover:border-accent/40" href={p.href}>
                <div className="h-1 w-full bg-gradient-to-r from-accent/0 via-accent/60 to-ops/0" />
                <div className="p-5">
                  <p className="text-xs tracking-[0.14em] text-dim">{t(`products.${p.id}.eyebrow`)}</p>
                  <h2 className="mt-2 text-xl text-ink">{t(`products.${p.id}.title`)}</h2>
                  <p className="mt-2 text-sm text-muted">{t(`products.${p.id}.summary`)}</p>
                </div>
              </A>
            </li>
          ))}
        </ul>
      </Section>
      <Section eyebrow={t('platformPage.loopEyebrow')} title={t('platformPage.loopTitle')}>
        <ProcessTimeline />
      </Section>
    </Layout>
  )
}
