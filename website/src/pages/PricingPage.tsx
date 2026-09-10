import { DemoForm } from '../components/DemoForm'
import { DemoJourney } from '../components/DemoJourney'
import { CustomerLoginLink } from '../components/CustomerLoginLink'
import { Layout } from '../components/Layout'
import { Ltr } from '../components/Ltr'
import { company } from '../content/site'
import { useI18n } from '../i18n'

export function PricingPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <div className="site-wrap grid items-start gap-12 py-16 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <p className="eyebrow">{t('pricingPage.eyebrow')}</p>
          <h1 className="display mt-3 text-4xl text-ink md:text-5xl">{t('pricingPage.title')}</h1>
          <p className="mt-5 text-lg text-muted">{t('pricingPage.lead')}</p>
          <p className="mt-6 text-sm text-muted">
            {t('pricingPage.emailLabel')}{' '}
            <a className="text-accent" href={`mailto:${company.emails.sales}`}>
              <Ltr>{company.emails.sales}</Ltr>
            </a>
          </p>
          <div className="mt-8">
            <DemoJourney />
          </div>
          <div className="mt-8">
            <CustomerLoginLink />
            <p className="mt-3 text-sm text-dim">{t('pricingPage.loginHint')}</p>
          </div>
        </div>
        <div className="lg:col-span-7">
          <p className="mb-4 text-sm font-medium text-ink">{t('demoJourney.formTitle')}</p>
          <DemoForm />
        </div>
      </div>
      <section className="site-wrap max-w-3xl pb-20">
        <h2 className="text-2xl text-ink">{t('pricingPage.faqsTitle')}</h2>
        <div className="mt-6 space-y-3">
          {[0, 1, 2, 3].map((i) => (
            <details key={i} className="rounded-[14px] border border-[var(--line)] p-4">
              <summary className="min-h-11 cursor-pointer font-medium text-accent">{t(`pricingPage.faqs.${i}.q`)}</summary>
              <p className="mt-3 text-sm text-muted">{t(`pricingPage.faqs.${i}.a`)}</p>
            </details>
          ))}
        </div>
      </section>
    </Layout>
  )
}
