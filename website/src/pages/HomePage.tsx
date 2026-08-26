import { ButtonLink } from '../components/Button'
import { FeaturedRail } from '../components/FeaturedRail'
import { Hero } from '../components/Hero'
import { InteractiveProduct } from '../components/InteractiveProduct'
import { Layout } from '../components/Layout'
import { PlatformTabs } from '../components/PlatformTabs'
import { ResourceGrid } from '../components/ResourceGrid'
import { Reveal } from '../components/Reveal'
import { Section } from '../components/Section'
import { StickySectionNav } from '../components/StickySectionNav'
import { capabilities, cta, howItWorks, proofPrinciples, solutions, threatStory } from '../content/site'

export function HomePage() {
  return (
    <Layout>
      <Hero />
      <FeaturedRail />
      <StickySectionNav />

      <Section id="why-us" eyebrow="Threat landscape" title="Complexity went up. Clarity has to follow.">
        <div className="grid gap-4 md:grid-cols-3">
          {threatStory.map((s) => (
            <Reveal key={s.step}>
              <article className="surface h-full p-6">
                <p className="font-mono text-xs text-accent">{s.step}</p>
                <h3 className="mt-3 text-xl text-ink">{s.title}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted">{s.body}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="platform" eyebrow="Platform" title="One loop. Seven confirmed surfaces." sub="Each area is in the product today — not a roadmap slide.">
        <PlatformTabs />
      </Section>

      <Section eyebrow="Interactive walkthrough" title="How an investigation reads" sub="Sample rows only. Filters and the investigation panel behave like the product; they are not connected to a tenant.">
        <InteractiveProduct />
      </Section>

      <Section id="capabilities" eyebrow="Capabilities" title="Outcomes, not adjectives">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((c) => (
            <Reveal key={c.title}>
              <a className="surface group block h-full p-6 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={c.href}>
                <h3 className="text-lg text-ink">{c.title}</h3>
                <p className="mt-2 text-sm text-muted">{c.body}</p>
                <p className="mt-4 text-sm font-semibold text-accent">
                  Learn more <span className="inline-block transition-transform group-hover:translate-x-0.5">→</span>
                </p>
              </a>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="how-it-works" eyebrow="How it works" title="Four stages. No ceremony.">
        <ol className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {howItWorks.map((s, i) => (
            <li key={s.id} className="surface p-6">
              <p className="font-mono text-xs text-ops">0{i + 1}</p>
              <h3 className="mt-3 text-xl text-ink">{s.title}</h3>
              <p className="mt-3 text-sm text-muted">{s.body}</p>
            </li>
          ))}
        </ol>
        <div className="mt-8">
          <ButtonLink variant="ghost" href="/technology/">
            Full technology walkthrough
          </ButtonLink>
        </div>
      </Section>

      <Section eyebrow="Solutions" title="Built for the people who have to decide">
        <div className="grid gap-4 lg:grid-cols-2">
          {solutions.map((s) => (
            <article key={s.id} id={s.id} className="surface p-6">
              <h3 className="text-xl text-ink">{s.title}</h3>
              <p className="mt-2 text-sm text-muted">{s.body}</p>
              <ul className="mt-4 space-y-1 text-sm text-muted">
                {s.points.map((p) => (
                  <li key={p}>▸ {p}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </Section>

      <Section id="proof" eyebrow="Proof" title="Built for security-critical environments" sub="We do not publish customer logos or analyst awards we do not have. These are operating principles you can inspect in the product and the legal pack.">
        <div className="grid gap-4 md:grid-cols-2">
          {proofPrinciples.map((p) => (
            <article key={p.title} className="surface p-6">
              <h3 className="text-lg text-ink">{p.title}</h3>
              <p className="mt-2 text-sm text-muted">{p.body}</p>
            </article>
          ))}
        </div>
      </Section>

      <Section id="resources" eyebrow="Resources" title="What we can actually publish">
        <ResourceGrid />
      </Section>

      <section id="contact" className="border-t border-[var(--line)] bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.12),transparent_55%)] py-24">
        <div className="site-wrap max-w-3xl text-center">
          <h2 className="display text-4xl text-ink md:text-5xl">See the evidence, then decide.</h2>
          <p className="mx-auto mt-4 max-w-xl text-lg text-muted">
            Book a demo of the Command Center, or start a trial if self-serve signup is enabled on this deployment.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
            <ButtonLink variant="ghost" href={cta.trial.href}>
              {cta.trial.label}
            </ButtonLink>
          </div>
        </div>
      </section>
    </Layout>
  )
}
