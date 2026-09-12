import { describe, it, expect } from 'vitest'
import { configuredItdrProviders, ITDR_PROVIDERS } from './itdrConnectors.js'

describe('configuredItdrProviders', () => {
  it('does not count the catalog when no tokens are stored', () => {
    expect(ITDR_PROVIDERS).toHaveLength(3)
    expect(configuredItdrProviders({})).toEqual([])
    expect(configuredItdrProviders(null)).toEqual([])
  })

  it('counts only providers with live credentials', () => {
    expect(
      configuredItdrProviders({
        entra: { access_token: 'gph' },
        okta: { domain: 'acme.okta.com' },
        google: { access_token: '  ' },
      }),
    ).toEqual(['entra'])
  })

  it('reads nested connectors.entra shape', () => {
    expect(
      configuredItdrProviders({
        connectors: { okta: { api_token: 'ssws', domain: 'acme.okta.com' } },
      }),
    ).toEqual(['okta'])
  })
})
