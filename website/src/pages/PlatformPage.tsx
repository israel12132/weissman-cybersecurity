import { Layout } from '../components/Layout'
import { PlatformTabs } from '../components/PlatformTabs'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { products } from '../content/products'
import { cta, howItWorks } from '../content/site'

export function PlatformPage() {
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">Platform</p>
        <h1 className="display mt-3 max-w-4xl text-4xl text-ink md:text-6xl">Detection, validation, prioritisation, and response in one control plane.</h1>
        <p className="mt-6 max-w-2xl text-lg text-muted">
          Weissman is not a scanner with a theme. Engines, agent, OAST, attack paths, SOAR, and the Command Center share one finding model and one audit trail.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
          <ButtonLink variant="ghost" href="/technology/">
            How it works
          </ButtonLink>
        </div>
      </header>
      <Section eyebrow="Modules" title="Confirmed product areas">
        <PlatformTabs />
      </Section>
      <Section eyebrow="Index" title="Every capability page">
        <ul className="grid gap-3 md:grid-cols-2">
          {products.map((p) => (
            <li key={p.id}>
              <a className="surface block p-5 hover:border-accent/40" href={p.href}>
                <p className="text-xs uppercase tracking-[0.14em] text-dim">{p.eyebrow}</p>
                <h2 className="mt-2 text-xl text-ink">{p.title}</h2>
                <p className="mt-2 text-sm text-muted">{p.summary}</p>
              </a>
            </li>
          ))}
        </ul>
      </Section>
      <Section eyebrow="Loop" title="The same four stages everywhere">
        <ol className="grid gap-4 md:grid-cols-4">
          {howItWorks.map((s) => (
            <li key={s.id} className="surface p-5">
              <h3 className="text-ink">{s.title}</h3>
              <p className="mt-2 text-sm text-muted">{s.body}</p>
            </li>
          ))}
        </ol>
      </Section>
    </Layout>
  )
}
