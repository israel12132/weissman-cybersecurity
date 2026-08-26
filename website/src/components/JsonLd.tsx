import { useEffect } from 'react'
import { company } from '../content/site'
import { metrics } from '../content/metrics'

export function JsonLd() {
  useEffect(() => {
    const org = {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: company.legalName,
      url: company.origin,
      email: company.emails.sales,
      address: {
        '@type': 'PostalAddress',
        addressLocality: 'Tel Aviv-Yafo',
        addressCountry: 'IL',
      },
    }
    const app = {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: 'Weissman Cybersecurity Platform',
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Web, Linux, macOS, Windows',
      url: company.origin,
      offers: {
        '@type': 'Offer',
        price: String(metrics.cloudPriceUsd.value),
        priceCurrency: 'USD',
      },
      description:
        'Autonomous offensive-security and active-defence platform with live probes, attack-path intelligence, and a SOC Command Center.',
    }

    const nodes = [org, app].map((data, i) => {
      const el = document.createElement('script')
      el.type = 'application/ld+json'
      el.id = `weissman-ld-${i}`
      el.text = JSON.stringify(data)
      document.head.appendChild(el)
      return el
    })
    return () => nodes.forEach((n) => n.remove())
  }, [])
  return null
}
