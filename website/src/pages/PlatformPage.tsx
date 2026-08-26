import { Layout } from '../components/Layout'
import { PlatformTabs } from '../components/PlatformTabs'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { A } from '../components/A'
import { products } from '../content/products'
import { howItWorksIds } from '../content/site'
import { useI18n } from '../i18n'

export function PlatformPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">{t('platformPage.eyebrow')}</p>
        <h1 className="display mt-3 max-w-4xl text-4xl text-ink md:text-6xl">{t('platformPage.title')}</h1>
        <p className="mt-6 max-w-2xl text-lg text-muted">{t('platformPage.lead')}</p>
        <div className="mt-8 flex flex-wrap gap-3">
          <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
          <ButtonLink variant="ghost" href="/technology/">
            {t('cta.howItWorks')}
          </ButtonLink>
        </div>
      </header>
      <Section eyebrow={t('platformPage.modulesEyebrow')} title={t('platformPage.modulesTitle')}>
        <PlatformTabs />
      </Section>
      <Section eyebrow={t('platformPage.indexEyebrow')} title={t('platformPage.indexTitle')}>
        <ul className="grid gap-3 md:grid-cols-2">
          {products.map((p) => (
            <li key={p.id}>
              <A className="surface block p-5 hover:border-accent/40" href={p.href}>
                <p className="text-xs uppercase tracking-[0.14em] text-dim">{t(`products.${p.id}.eyebrow`)}</p>
                <h2 className="mt-2 text-xl text-ink">{t(`products.${p.id}.title`)}</h2>
                <p className="mt-2 text-sm text-muted">{t(`products.${p.id}.summary`)}</p>
              </A>
            </li>
          ))}
        </ul>
      </Section>
      <Section eyebrow={t('platformPage.loopEyebrow')} title={t('platformPage.loopTitle')}>
        <ol className="grid gap-4 md:grid-cols-4">
          {howItWorksIds.map((id) => (
            <li key={id} className="surface p-5">
              <h3 className="text-ink">{t(`howItWorks.${id}.title`)}</h3>
              <p className="mt-2 text-sm text-muted">{t(`howItWorks.${id}.body`)}</p>
            </li>
          ))}
        </ol>
      </Section>
    </Layout>
  )
}
