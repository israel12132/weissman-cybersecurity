import { Layout } from '../components/Layout'
import { ButtonLink } from '../components/Button'
import { pricing, pricingFaqs } from '../content/site'

export function PricingPage() {
  const cards = [pricing.selfHosted, pricing.cloud, pricing.enterprise]
  return (
    <Layout>
      <header className="site-wrap py-16 text-center">
        <p className="eyebrow">Pricing</p>
        <h1 className="display mx-auto mt-3 max-w-3xl text-4xl text-ink md:text-5xl">Pay for operations, not a feature matrix.</h1>
        <p className="mx-auto mt-5 max-w-2xl text-lg text-muted">
          Self-hosted is free forever. Cloud SaaS scales with usage. Availability numbers follow SLA_AND_STATUS.md, not older marketing copy.
        </p>
      </header>
      <section className="site-wrap grid gap-4 pb-16 lg:grid-cols-3">
        {cards.map((card, i) => (
          <article key={card.name} className={`surface flex flex-col p-6 ${i === 1 ? 'border-accent/40 shadow-[var(--shadow)]' : ''}`}>
            <p className="text-xs uppercase tracking-[0.16em] text-accent">{card.tier}</p>
            <h2 className="mt-2 text-2xl text-ink">{card.name}</h2>
            <p className="mt-4 text-3xl text-ink">
              {card.price}
              {card.unit && <span className="text-base text-dim">{card.unit}</span>}
            </p>
            <p className="mt-2 text-sm text-muted">{card.blurb}</p>
            <ul className="mt-6 flex-1 space-y-2 text-sm text-muted">
              {card.items.map((item) => (
                <li key={item}>▸ {item}</li>
              ))}
            </ul>
            <div className="mt-8">
              <ButtonLink variant={i === 1 ? 'primary' : 'ghost'} href={card.cta.href} className="w-full">
                {card.cta.label}
              </ButtonLink>
            </div>
          </article>
        ))}
      </section>
      <section className="site-wrap max-w-3xl pb-20">
        <h2 className="text-2xl text-ink">Questions we already answer</h2>
        <div className="mt-6 space-y-3">
          {pricingFaqs.map((f) => (
            <details key={f.q} className="surface p-4">
              <summary className="min-h-11 cursor-pointer font-medium text-accent">{f.q}</summary>
              <p className="mt-3 text-sm text-muted">{f.a}</p>
            </details>
          ))}
        </div>
      </section>
    </Layout>
  )
}
