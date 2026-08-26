import { useEffect } from 'react'
import { company } from '../content/site'
import { localeMeta } from '../i18n/locale'
import { useI18n } from '../i18n'

function localeHome(origin: string, locale: 'en' | 'he') {
  return locale === 'he' ? `${origin}/he/` : `${origin}/`
}

export function JsonLd() {
  const { locale, t } = useI18n()
  useEffect(() => {
    const org = {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: company.legalName,
      url: localeHome(company.origin, locale),
      email: company.emails.sales,
      inLanguage: localeMeta[locale].htmlLang,
      address: {
        '@type': 'PostalAddress',
        addressLocality: locale === 'he' ? 'תל אביב-יפו' : 'Tel Aviv-Yafo',
        addressCountry: 'IL',
      },
    }
    const app = {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: t('brand.product'),
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Web, Linux, macOS, Windows',
      url: localeHome(company.origin, locale),
      inLanguage: localeMeta[locale].htmlLang,
      offers: {
        '@type': 'Offer',
        url: `${localeHome(company.origin, locale)}contact/`,
        description: t('pricingPage.lead'),
      },
      description: t('brand.jsonLdDescription'),
    }

    const payloads = [org, app]
    const nodes = payloads.map((data, i) => {
      const id = `weissman-ld-${i}`
      let el = document.getElementById(id) as HTMLScriptElement | null
      const created = !el
      if (!el) {
        el = document.createElement('script')
        el.type = 'application/ld+json'
        el.id = id
        document.head.appendChild(el)
      }
      el.text = JSON.stringify(data)
      return created ? el : null
    })
    return () => nodes.forEach((n) => n?.remove())
  }, [locale, t])
  return null
}
