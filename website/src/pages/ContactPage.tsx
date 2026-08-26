import { DemoForm } from '../components/DemoForm'
import { Layout } from '../components/Layout'
import { Ltr } from '../components/Ltr'
import { company } from '../content/site'
import { useI18n } from '../i18n'

export function ContactPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <div className="site-wrap grid gap-12 py-16 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <p className="eyebrow">{t('contactPage.eyebrow')}</p>
          <h1 className="display mt-3 text-4xl text-ink md:text-5xl">{t('contactPage.title')}</h1>
          <p className="mt-5 text-lg text-muted">{t('contactPage.lead')}</p>
          <ul className="mt-8 space-y-2 text-sm text-muted">
            <li>
              {t('contactPage.sales')}:{' '}
              <a className="text-accent" href={`mailto:${company.emails.sales}`}>
                <Ltr>{company.emails.sales}</Ltr>
              </a>
            </li>
            <li>
              {t('contactPage.security')}:{' '}
              <a className="text-accent" href={`mailto:${company.emails.security}`}>
                <Ltr>{company.emails.security}</Ltr>
              </a>
            </li>
            <li>
              {t('contactPage.support')}:{' '}
              <a className="text-accent" href={`mailto:${company.emails.support}`}>
                <Ltr>{company.emails.support}</Ltr>
              </a>
            </li>
          </ul>
        </div>
        <div className="lg:col-span-7">
          <DemoForm />
        </div>
      </div>
    </Layout>
  )
}
