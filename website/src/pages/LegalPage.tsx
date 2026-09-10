import { Layout } from '../components/Layout'
import { useI18n } from '../i18n'
import terms from '../content/legal/terms.html?raw'
import privacy from '../content/legal/privacy.html?raw'
import termsHe from '../content/legal/terms-he.html?raw'
import privacyHe from '../content/legal/privacy-he.html?raw'
import dpa from '../content/legal/dpa.html?raw'
import subprocessors from '../content/legal/subprocessors.html?raw'
import security from '../content/legal/security-policy.html?raw'

const docs: Record<string, string> = {
  terms,
  privacy,
  'terms-he': termsHe,
  'privacy-he': privacyHe,
  dpa,
  subprocessors,
  'security-policy': security,
}

const ENGLISH_BINDING = new Set(['dpa', 'subprocessors', 'security-policy'])

export function LegalPage({ doc }: { doc: string }) {
  const { t, locale } = useI18n()
  const html = docs[doc]
  const showEnglishBanner = locale === 'he' && (ENGLISH_BINDING.has(doc) || !html)
  const approvedHe = doc === 'terms-he' || doc === 'privacy-he'
  return (
    <Layout>
      {showEnglishBanner && !approvedHe && (
        <p className="site-wrap mt-10 rounded-[12px] border border-risk/40 bg-risk/10 px-4 py-3 text-sm text-risk">
          {t('legal.englishOnly')}
        </p>
      )}
      <article
        className="legal-doc px-4 py-16"
        lang={showEnglishBanner ? 'en' : undefined}
        dir={showEnglishBanner ? 'ltr' : undefined}
        dangerouslySetInnerHTML={{ __html: html || `<p>${t('legal.missing')}</p>` }}
      />
    </Layout>
  )
}
