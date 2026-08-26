import { ButtonLink } from '../components/Button'
import { Layout } from '../components/Layout'
import { ProductVisual } from '../components/ProductVisual'
import { Section } from '../components/Section'
import { cta } from '../content/site'
import { products, type Product } from '../content/products'

const accents: Record<Product['accent'], string> = {
  accent: 'var(--accent)',
  risk: 'var(--risk)',
  ops: 'var(--ops)',
}

export function ProductCapabilityPage({ productId }: { productId: string }) {
  const product = products.find((p) => p.id === productId)
  if (!product) {
    return (
      <Layout>
        <Section title="Not found">
          <p className="text-muted">This capability page is not in the catalog.</p>
        </Section>
      </Layout>
    )
  }
  const color = accents[product.accent]
  const related = products.filter((p) => p.id !== product.id).slice(0, 3)

  return (
    <Layout>
      <header className="border-b border-[var(--line)] py-16">
        <div className="site-wrap grid items-center gap-10 lg:grid-cols-12">
          <div className="lg:col-span-6">
            <p className="eyebrow" style={{ color }}>
              {product.eyebrow}
            </p>
            <h1 className="display mt-3 text-4xl text-ink md:text-5xl">{product.title}</h1>
            <p className="mt-5 max-w-xl text-lg text-muted">{product.summary}</p>
            <div className="mt-8 flex flex-wrap gap-3">
              <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
              <ButtonLink variant="ghost" href="/platform/">
                Platform overview
              </ButtonLink>
            </div>
          </div>
          <div className="lg:col-span-6">
            <ProductVisual accent={color} />
          </div>
        </div>
      </header>

      <nav aria-label="On this page" className="sticky top-[var(--nav-h)] z-30 border-b border-[var(--line)] bg-[rgba(7,9,12,0.88)] backdrop-blur">
        <ul className="site-wrap flex gap-2 overflow-x-auto py-2 text-sm">
          {[
            ['outcomes', 'Outcomes'],
            ['capabilities', 'Capabilities'],
            ['technical', 'Technical'],
            ['workflow', 'Workflow'],
            ['related', 'Related'],
          ].map(([id, label]) => (
            <li key={id}>
              <a className="inline-flex min-h-11 items-center px-3 text-muted hover:text-ink" href={`#${id}`}>
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <Section id="outcomes" eyebrow="Outcomes" title="What changes when this is on">
        <div className="grid gap-4 md:grid-cols-3">
          {product.outcomes.map((o) => (
            <article key={o} className="surface p-5 text-sm text-muted">
              {o}
            </article>
          ))}
        </div>
      </Section>

      <Section id="capabilities" eyebrow="Capabilities" title="In the product">
        <ul className="grid gap-3 md:grid-cols-2">
          {product.capabilities.map((c) => (
            <li key={c} className="surface p-4 text-sm text-muted">
              {c}
            </li>
          ))}
        </ul>
      </Section>

      <Section id="technical" eyebrow="Technical" title="How it is actually built">
        <p className="max-w-3xl text-muted">{product.technical}</p>
      </Section>

      <Section id="workflow" eyebrow="Workflow" title="Architecture in three moves">
        <ol className="grid gap-4 md:grid-cols-3">
          {product.workflow.map((w, i) => (
            <li key={w} className="surface p-5">
              <p className="font-mono text-xs text-accent">0{i + 1}</p>
              <p className="mt-2 text-ink">{w}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section id="related" eyebrow="Related" title="Nearby in the platform">
        <div className="grid gap-4 md:grid-cols-3">
          {related.map((p) => (
            <a key={p.id} href={p.href} className="surface block p-5 hover:border-accent/40">
              <p className="text-xs uppercase tracking-[0.14em] text-dim">{p.eyebrow}</p>
              <h3 className="mt-2 text-ink">{p.title}</h3>
            </a>
          ))}
        </div>
      </Section>

      <section className="border-t border-[var(--line)] py-20">
        <div className="site-wrap text-center">
          <h2 className="display text-3xl text-ink">Walk this in the Command Center</h2>
          <div className="mt-6">
            <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
          </div>
        </div>
      </section>
    </Layout>
  )
}
