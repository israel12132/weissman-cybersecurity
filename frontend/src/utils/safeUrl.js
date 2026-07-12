// Guard against `javascript:`/`data:` and other non-navigational URI schemes reaching an <a href>.
// React does NOT sanitize href at runtime, so a stored `javascript:alert(1)` from an external feed
// (e.g. synced exploit payload source_url) would execute on click. Allow only http/https.

export function isHttpUrl(value) {
  if (typeof value !== 'string' || value.trim() === '') return false
  try {
    const u = new URL(value, window.location.origin)
    return u.protocol === 'http:' || u.protocol === 'https:'
  } catch {
    return false
  }
}

// Returns the URL when it is a safe http(s) link, otherwise undefined — so callers can fall back to
// rendering plain text instead of an actionable link.
export function safeHttpHref(value) {
  return isHttpUrl(value) ? value : undefined
}
