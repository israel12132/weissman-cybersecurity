import { Layout } from '../components/Layout'
import { ButtonLink } from '../components/Button'
import { metrics } from '../content/metrics'
import { company } from '../content/site'
import { useI18n } from '../i18n'

export function PricingPage() {
  const { t, n } = useI18n()
  const cards = [
    {
      id: 'selfHosted' as const,
      price: '$0',
      href: company.github,
      highlight: false,
    },
    {
      id: 'cloud' as const,
      price: `$${metrics.cloudPriceUsd.value}`,
      href: '/signup.html',
      highlight: true,
    },
    {
      id: 'enterprise' as const,
      price: t('pricingPage.tiers.enterprise.price'),
      href: '/contact/',
      highlight: false,
    },
  ]
  const vars = {
    engines: n(metrics.productionEngines.value),
    sla: metrics.slaUptime.value,
    days: n(metrics.trialDays.value),
  }

  return (
    <Layout>
      <header className="site-wrap py-16 text-center">
        <p className="eyebrow">{t('pricingPage.eyebrow')}</p>
        <h1 className="display mx-auto mt-3 max-w-3xl text-4xl text-ink md:text-5xl">{t('pricingPage.title')}</h1>
        <p className="mx-auto mt-5 max-w-2xl text-lg text-muted">{t('pricingPage.lead')}</p>
      </header>
      <section className="site-wrap grid gap-4 pb-16 lg:grid-cols-3">
        {cards.map((card) => {
          const itemCount = card.id === 'cloud' ? 7 : 7
          return (
            <article
              key={card.id}
              className={`surface flex flex-col p-6 ${card.highlight ? 'border-accent/40 shadow-[var(--shadow)]' : ''}`}
            >
              <p className="text-xs uppercase tracking-[0.16em] text-accent">{t(`pricingPage.tiers.${card.id}.tier`)}</p>
              <h2 className="mt-2 text-2xl text-ink">{t(`pricingPage.tiers.${card.id}.name`)}</h2>
              <p className="mt-4 text-3xl text-ink">
                <span dir="ltr">{card.price}</span>
                {card.id !== 'enterprise' && (
                  <span className="text-base text-dim">{t(`pricingPage.tiers.${card.id}.unit`)}</span>
                )}
              </p>
              <p className="mt-2 text-sm text-muted">{t(`pricingPage.tiers.${card.id}.blurb`)}</p>
              <ul className="mt-6 flex-1 space-y-2 text-sm text-muted">
                {Array.from({ length: itemCount }, (_, i) => (
                  <li key={i}>▸ {t(`pricingPage.tiers.${card.id}.items.${i}`, vars)}</li>
                ))}
              </ul>
              <div className="mt-8">
                <ButtonLink variant={card.highlight ? 'primary' : 'ghost'} href={card.href} className="w-full">
                  {t(`pricingPage.tiers.${card.id}.cta`)}
                </ButtonLink>
              </div>
            </article>
          )
        })}
      </section>
      <section className="site-wrap max-w-3xl pb-20">
        <h2 className="text-2xl text-ink">{t('pricingPage.faqsTitle')}</h2>
        <div className="mt-6 space-y-3">
          {[0, 1, 2, 3].map((i) => (
            <details key={i} className="surface p-4">
              <summary className="min-h-11 cursor-pointer font-medium text-accent">{t(`pricingPage.faqs.${i}.q`)}</summary>
              <p className="mt-3 text-sm text-muted">{t(`pricingPage.faqs.${i}.a`)}</p>
            </details>
          ))}
        </div>
      </section>
    </Layout>
  )
}
