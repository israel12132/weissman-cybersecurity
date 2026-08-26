import { Layout } from '../components/Layout'
import { ResourceGrid } from '../components/ResourceGrid'
import { Section } from '../components/Section'

export function ResourcesPage() {
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">Resources</p>
        <h1 className="display mt-3 text-4xl text-ink md:text-5xl">Published material only.</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">
          No invented case studies or analyst notes. If a category is empty later, it stays empty until there is something real to put in it.
        </p>
      </header>
      <Section>
        <ResourceGrid />
      </Section>
    </Layout>
  )
}
