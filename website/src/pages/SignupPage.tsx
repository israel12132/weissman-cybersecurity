import { CustomerLoginLink } from '../components/CustomerLoginLink'
import { DemoForm } from '../components/DemoForm'
import { Layout } from '../components/Layout'
import { Ltr } from '../components/Ltr'
import { company } from '../content/site'
import { useI18n } from '../i18n'

export function SignupPage() {
  const { t } = useI18n()
  return (
    <Layout announce={false}>
      <div className="site-wrap grid items-start gap-12 py-16 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <h1 className="display text-4xl text-ink md:text-5xl">{t('signupPage.title')}</h1>
          <p className="mt-4 text-lg text-muted">{t('signupPage.lead')}</p>
          <p className="mt-6 text-sm text-muted">
            {t('pricingPage.emailLabel')}{' '}
            <a className="text-accent" href={`mailto:${company.emails.sales}`}>
              <Ltr>{company.emails.sales}</Ltr>
            </a>
          </p>
          <div className="mt-8">
            <p className="text-sm text-dim">{t('signupPage.haveAccount')}</p>
            <div className="mt-3">
              <CustomerLoginLink />
            </div>
          </div>
        </div>
        <div className="lg:col-span-7">
          <p className="mb-4 text-sm font-medium text-ink">{t('demoJourney.formTitle')}</p>
          <DemoForm />
        </div>
      </div>
    </Layout>
  )
}
