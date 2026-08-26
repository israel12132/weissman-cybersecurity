import { ButtonLink } from '../components/Button'
import { Layout } from '../components/Layout'
import { ProductScene } from '../components/ProductScene'
import { Section } from '../components/Section'
import { A } from '../components/A'
import { products, type Product } from '../content/products'
import { useI18n } from '../i18n'

const accents: Record<Product['accent'], string> = {
  accent: 'var(--accent)',
  risk: 'var(--risk)',
  ops: 'var(--ops)',
}

export function ProductCapabilityPage({ productId }: { productId: string }) {
  const { t } = useI18n()
  const product = products.find((p) => p.id === productId)
  if (!product) {
    return (
      <Layout>
        <Section title={t('productPage.notFound')}>
          <p className="text-muted">{t('productPage.missing')}</p>
        </Section>
      </Layout>
    )
  }
  const color = accents[product.accent]
  const related = products.filter((p) => p.id !== product.id).slice(0, 3)
  const nav = [
    ['outcomes', t('productPage.outcomes')],
    ['capabilities', t('productPage.capabilities')],
    ['technical', t('productPage.technical')],
    ['workflow', t('productPage.workflow')],
    ['related', t('productPage.related')],
  ] as const

  return (
    <Layout>
      <header className="border-b border-[var(--line)] py-16">
        <div className="site-wrap grid items-center gap-10 lg:grid-cols-12">
          <div className="lg:col-span-6">
            <p className="eyebrow" style={{ color }}>
              {t(`products.${product.id}.eyebrow`)}
            </p>
            <h1 className="display mt-3 text-4xl text-ink md:text-5xl">{t(`products.${product.id}.title`)}</h1>
            <p className="mt-5 max-w-xl text-lg text-muted">{t(`products.${product.id}.summary`)}</p>
            <div className="mt-8 flex flex-wrap gap-3">
              <ButtonLink href="/contact/" analyticsEvent="demo_cta_click" analyticsPayload={{ placement: 'product' }}>
                {t('cta.bookDemo')}
              </ButtonLink>
              <ButtonLink variant="ghost" href="/platform/">
                {t('cta.platformOverview')}
              </ButtonLink>
            </div>
          </div>
          <div className="lg:col-span-6">
            <ProductScene productId={product.id} accent={product.accent} />
          </div>
        </div>
      </header>

      <nav aria-label={t('a11y.onThisPage')} className="sticky top-[var(--nav-h)] z-30 border-b border-[var(--line)] bg-[rgba(7,9,12,0.88)] backdrop-blur">
        <ul className="site-wrap flex gap-2 overflow-x-auto py-2 text-sm">
          {nav.map(([id, label]) => (
            <li key={id}>
              <a className="inline-flex min-h-11 items-center px-3 text-muted hover:text-ink" href={`#${id}`}>
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <Section id="outcomes" eyebrow={t('productPage.outcomes')} title={t('productPage.outcomesTitle')}>
        <div className="grid gap-4 md:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <article key={i} className="surface p-5 text-sm text-muted">
              {t(`products.${product.id}.outcomes.${i}`)}
            </article>
          ))}
        </div>
      </Section>

      <Section id="capabilities" eyebrow={t('productPage.capabilities')} title={t('productPage.capabilitiesTitle')}>
        <ul className="grid gap-3 md:grid-cols-2">
          {[0, 1, 2, 3].map((i) => (
            <li key={i} className="surface p-4 text-sm text-muted">
              {t(`products.${product.id}.capabilities.${i}`)}
            </li>
          ))}
        </ul>
      </Section>

      <Section id="technical" eyebrow={t('productPage.technical')} title={t('productPage.technicalTitle')}>
        <p className="max-w-3xl text-muted">{t(`products.${product.id}.technical`)}</p>
      </Section>

      <Section id="workflow" eyebrow={t('productPage.workflow')} title={t('productPage.workflowTitle')}>
        <ol className="grid gap-4 md:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <li key={i} className="surface p-5">
              <p className="font-mono text-xs text-accent">0{i + 1}</p>
              <p className="mt-2 text-ink">{t(`products.${product.id}.workflow.${i}`)}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section id="related" eyebrow={t('productPage.related')} title={t('productPage.relatedTitle')}>
        <div className="grid gap-4 md:grid-cols-3">
          {related.map((p) => (
            <A key={p.id} href={p.href} className="surface block p-5 hover:border-accent/40">
              <p className="text-xs uppercase tracking-[0.14em] text-dim">{t(`products.${p.id}.eyebrow`)}</p>
              <h3 className="mt-2 text-ink">{t(`products.${p.id}.title`)}</h3>
            </A>
          ))}
        </div>
      </Section>

      <section className="border-t border-[var(--line)] py-20">
        <div className="site-wrap text-center">
          <h2 className="display text-3xl text-ink">{t('productPage.walkTitle')}</h2>
          <div className="mt-6">
            <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
          </div>
        </div>
      </section>
    </Layout>
  )
}
