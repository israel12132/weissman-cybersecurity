import { Layout } from '../components/Layout'
import { SignupForm } from '../components/SignupForm'
import { useI18n } from '../i18n'

export function SignupPage() {
  const { t } = useI18n()
  return (
    <Layout announce={false}>
      <div className="site-wrap flex min-h-[70vh] items-center justify-center py-16">
        <div className="surface w-full max-w-md p-8">
          <h1 className="display text-2xl text-ink">{t('signupPage.title')}</h1>
          <p className="mt-2 text-sm text-muted">{t('signupPage.lead')}</p>
          <div className="mt-8">
            <SignupForm />
          </div>
          <p className="mt-8 text-center text-xs text-dim">
            {t('signupPage.haveAccount')}{' '}
            <a className="text-accent" href="/command-center/login">
              {t('cta.signIn')}
            </a>
          </p>
        </div>
      </div>
    </Layout>
  )
}
