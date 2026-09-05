import { describe, expect, it } from 'vitest'
import { alternatePath, localizeHref, localeFromPathname, stripLocalePrefix } from './locale'
import { en } from './messages/en'
import { he } from './messages/he'
import { listMessageKeys, translate } from './t'
import { products } from '../content/products'
import { resources } from '../content/resources'
import { metrics } from '../content/metrics'
import { company, CUSTOMER_LOGIN_HREF } from '../content/site'

describe('locale routing', () => {
  it('prefixes Hebrew marketing paths and keeps English unprefixed', () => {
    expect(localizeHref('/', 'he')).toBe('/he/')
    expect(localizeHref('/platform/', 'he')).toBe('/he/platform/')
    expect(localizeHref('/pricing.html', 'he')).toBe('/he/pricing.html')
    expect(localizeHref('/he/platform/', 'en')).toBe('/platform/')
    expect(localizeHref('/contact/#form', 'he')).toBe('/he/contact/#form')
  })

  it('maps approved legal pairs instead of inventing /he/terms.html', () => {
    expect(localizeHref('/terms.html', 'he')).toBe('/terms-he.html')
    expect(localizeHref('/privacy.html', 'he')).toBe('/privacy-he.html')
    expect(localizeHref('/terms-he.html', 'en')).toBe('/terms.html')
  })

  it('does not localize Command Center, API, or mailto', () => {
    expect(localizeHref('/command-center/login', 'he')).toBe('/command-center/login')
    expect(localizeHref('/api/docs/', 'he')).toBe('/api/docs/')
    expect(localizeHref('mailto:sales@weissman.io', 'he')).toBe('mailto:sales@weissman.io')
    expect(localizeHref('/status', 'he')).toBe('/status')
  })

  it('reads locale from path', () => {
    expect(localeFromPathname('/he/platform/')).toBe('he')
    expect(localeFromPathname('/terms-he.html')).toBe('he')
    expect(localeFromPathname('/platform/')).toBe('en')
    expect(stripLocalePrefix('/he/pricing.html')).toBe('/pricing.html')
  })

  it('keeps the visitor on the equivalent page when switching language', () => {
    expect(alternatePath('/platform/endpoint-protection/', 'he')).toBe('/he/platform/endpoint-protection/')
    expect(alternatePath('/he/platform/endpoint-protection/', 'en')).toBe('/platform/endpoint-protection/')
    expect(alternatePath('/he/contact/#form', 'en')).toBe('/contact/#form')
    expect(alternatePath('/pricing.html', 'he')).toBe('/he/pricing.html')
    expect(alternatePath('/he/dpa.html', 'en')).toBe('/dpa.html')
  })
})

describe('message catalogs', () => {
  it('covers every English key in Hebrew', () => {
    const enKeys = listMessageKeys(en)
    const heKeys = new Set(listMessageKeys(he))
    const missing = enKeys.filter((k) => !heKeys.has(k))
    expect(missing).toEqual([])
  })

  it('falls back to English for a missing key', () => {
    expect(translate('he', 'cta.bookDemo')).toBe('לתיאום הדגמה')
    expect(translate('he', 'does.not.exist')).toBe('does.not.exist')
  })
})

describe('content integrity', () => {
  it('lists seven product modules', () => {
    expect(products).toHaveLength(7)
    for (const p of products) {
      expect(p.href.startsWith('/platform/')).toBe(true)
    }
  })

  it('does not invent empty resource categories as fake papers', () => {
    expect(resources.every((r) => r.href.length > 0)).toBe(true)
  })

  it('keeps engine counts honest', () => {
    expect(metrics.productionEngines.value).toBe(573)
    expect(metrics.liveProbes.value).toBe(313)
    expect(metrics.slaUptime.value).toBe('99.95%')
  })

  it('routes commercial contact to the sales mailbox and live Command Center login', () => {
    expect(company.emails.sales).toBe('weissmancybersecurity@gmail.com')
    expect(CUSTOMER_LOGIN_HREF).toBe('/command-center/login')
    expect(localizeHref(CUSTOMER_LOGIN_HREF, 'he')).toBe('/command-center/login')
  })

  it('does not advertise packaged website prices', () => {
    expect(en.pricingPage).not.toHaveProperty('tiers')
    expect(he.pricingPage).not.toHaveProperty('tiers')
    expect(JSON.stringify(en) + JSON.stringify(he)).not.toMatch(/\$499/)
    expect(metrics).not.toHaveProperty('cloudPriceUsd')
    expect(metrics).not.toHaveProperty('trialDays')
  })
})
