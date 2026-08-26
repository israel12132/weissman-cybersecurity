import { Layout } from '../components/Layout'
import { Section } from '../components/Section'
import { ButtonLink } from '../components/Button'
import { howItWorks, cta } from '../content/site'
import { metrics } from '../content/metrics'

export function TechnologyPage() {
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">Technology</p>
        <h1 className="display mt-3 max-w-3xl text-4xl text-ink md:text-5xl">Observe. Analyse. Validate. Respond.</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">
          The orchestrator is a scoped loop, not a slogan. Scope is enforced before packets. Findings persist only from live probes. Blind classes wait on OAST. Response is audited.
        </p>
      </header>
      <Section eyebrow="Stages" title="Mapped to the running system">
        <ol className="space-y-4">
          {howItWorks.map((s, i) => (
            <li key={s.id} className="surface grid gap-4 p-6 md:grid-cols-12">
              <p className="font-mono text-accent md:col-span-2">0{i + 1}</p>
              <div className="md:col-span-10">
                <h2 className="text-2xl text-ink">{s.title}</h2>
                <p className="mt-2 text-muted">{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </Section>
      <Section eyebrow="Integrity" title="Numbers you can re-run">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[metrics.productionEngines, metrics.liveProbes, metrics.mitreTechniques, metrics.agentDetections].map((m) => (
            <div key={m.label} className="surface p-5">
              <dt className="text-xs uppercase tracking-[0.14em] text-dim">{m.label}</dt>
              <dd className="mt-2 font-mono text-3xl text-accent">{m.value}</dd>
              <p className="mt-2 font-mono text-[0.65rem] text-dim">{m.verify}</p>
            </div>
          ))}
        </dl>
      </Section>
      <Section>
        <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
      </Section>
    </Layout>
  )
}
