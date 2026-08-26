import { Layout } from '../components/Layout'
import { ButtonLink } from '../components/Button'
import { useI18n } from '../i18n'

export function NotFoundPage() {
  const { t } = useI18n()
  return (
    <Layout announce={false}>
      <div className="site-wrap py-24 text-center">
        <p className="eyebrow">{t('notFound.eyebrow')}</p>
        <h1 className="display mt-3 text-4xl text-ink">{t('notFound.title')}</h1>
        <p className="mx-auto mt-4 max-w-md text-muted">{t('notFound.body')}</p>
        <div className="mt-8 flex justify-center gap-3">
          <ButtonLink href="/">{t('cta.home')}</ButtonLink>
          <ButtonLink variant="ghost" href="/platform/">
            {t('cta.platform')}
          </ButtonLink>
        </div>
      </div>
    </Layout>
  )
}
