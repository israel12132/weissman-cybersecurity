/** IdP ids the Command Center can pull. Catalog size is not live posture. */
export const ITDR_PROVIDERS = ['entra', 'okta', 'google']

const TOKEN_KEYS = {
  entra: ['access_token', 'token', 'graph_token'],
  okta: ['api_token', 'token', 'ssws'],
  google: ['access_token', 'token'],
}

function sliceForProvider(connectors, provider) {
  if (!connectors || typeof connectors !== 'object') return null
  const direct = connectors[provider]
  if (direct && typeof direct === 'object') return direct
  const nested = connectors.connectors?.[provider]
  if (nested && typeof nested === 'object') return nested
  return connectors
}

function hasAnyToken(slice, keys) {
  if (!slice || typeof slice !== 'object') return false
  return keys.some((k) => typeof slice[k] === 'string' && slice[k].trim().length > 0)
}

/**
 * Providers that actually have credentials for a live pull.
 * Never report the catalog length (3) as armed connectors.
 */
export function configuredItdrProviders(connectors, providers = ITDR_PROVIDERS) {
  return providers.filter((p) => hasAnyToken(sliceForProvider(connectors, p), TOKEN_KEYS[p] || ['token']))
}
