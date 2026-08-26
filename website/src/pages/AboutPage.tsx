import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { about, company } from '../content/site'

export function AboutPage() {
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">Company</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">{company.legalName}</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">{about.lede}</p>
      </header>
      <Section title="How we operate">
        <ul className="max-w-3xl space-y-4 text-muted">
          {about.points.map((p) => (
            <li key={p} className="surface p-5">
              {p}
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Contact">
        <dl className="grid gap-4 sm:grid-cols-2">
          {Object.entries(company.emails).map(([k, v]) => (
            <div key={k} className="surface p-5">
              <dt className="text-xs uppercase tracking-[0.14em] text-dim">{k}</dt>
              <dd className="mt-2">
                <a className="text-accent" href={`mailto:${v}`}>
                  {v}
                </a>
              </dd>
            </div>
          ))}
        </dl>
        <p className="mt-8 text-sm text-dim">
          Registered address: {company.location}. Company number: {company.companyIdIsrael} — filled after incorporation; not invented here.
        </p>
      </Section>
    </Layout>
  )
}
