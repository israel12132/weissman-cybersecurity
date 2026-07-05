/**
 * Hide E2E / Playwright sandbox clients from operator sidebar by default.
 * Toggle: localStorage `weissman.show_sandbox_clients` = '1'
 */

const SANDBOX_NAME = /^(E2E\b|Playwright\b|e2e[\s_-])/i

export function isSandboxClient(client) {
  if (!client) return false
  const name = String(client.name || client.label || '').trim()
  if (SANDBOX_NAME.test(name)) return true
  if (client.is_sandbox === true || client.sandbox === true) return true
  return false
}

export function shouldShowSandboxClients() {
  try {
    return localStorage.getItem('weissman.show_sandbox_clients') === '1'
  } catch {
    return false
  }
}

/** Production roster — sandbox clients hidden unless explicitly toggled. */
export function filterClientsForOperatorRoster(clients) {
  if (!Array.isArray(clients)) return []
  if (shouldShowSandboxClients()) return clients
  return clients.filter((c) => !isSandboxClient(c))
}
