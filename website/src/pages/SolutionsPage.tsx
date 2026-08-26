import { useState } from 'react'
import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { solutions, cta } from '../content/site'

export function SolutionsPage() {
  const [id, setId] = useState<string>(solutions[0].id)
  const active = solutions.find((s) => s.id === id) ?? solutions[0]

  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">Solutions</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">Same platform. Different questions.</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">
          Weissman is sold to operators, not industries we invented. These are the audiences already implied by the product: executives, SOC, research, infrastructure, and teams that cannot send data to a public model.
        </p>
      </header>
      <Section>
        <div className="grid gap-8 lg:grid-cols-12">
          <div className="flex flex-col gap-2 lg:col-span-4" role="tablist" aria-label="Audiences">
            {solutions.map((s) => (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={s.id === id}
                className={`min-h-11 rounded-[12px] px-4 text-left text-sm ${s.id === id ? 'bg-elevated text-ink' : 'text-muted'}`}
                onClick={() => setId(s.id)}
              >
                {s.title}
              </button>
            ))}
          </div>
          <article className="surface p-6 lg:col-span-8" role="tabpanel">
            <h2 className="text-2xl text-ink">{active.title}</h2>
            <p className="mt-3 text-muted">{active.body}</p>
            <ul className="mt-6 space-y-2 text-sm text-muted">
              {active.points.map((p) => (
                <li key={p}>▸ {p}</li>
              ))}
            </ul>
            <div className="mt-8">
              <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
            </div>
          </article>
        </div>
      </Section>
    </Layout>
  )
}
