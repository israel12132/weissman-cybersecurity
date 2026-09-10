import { Layout } from '../components/Layout'
import { ResourceGrid } from '../components/ResourceGrid'
import { Section } from '../components/Section'
import { useI18n } from '../i18n'

export function ResourcesPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <header className="site-wrap py-16">
        <p className="eyebrow">{t('resourcesPage.eyebrow')}</p>
        <h1 className="display mt-3 text-4xl text-ink md:text-5xl">{t('resourcesPage.title')}</h1>
        <p className="mt-5 max-w-2xl text-lg text-muted">{t('resourcesPage.lead')}</p>
      </header>
      <Section>
        <ResourceGrid />
      </Section>
    </Layout>
  )
}
