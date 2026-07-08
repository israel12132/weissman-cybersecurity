/**
 * Finding-suppression expiry status helpers.
 *
 * A suppression silences a finding signature until an optional `expires_at`.
 * These pure helpers classify a suppression as expired / expiring-soon so the
 * registry UI can colour and filter it. `now` is injectable for testing.
 */

const SOON_WINDOW_MS = 7 * 86_400_000 // 7 days

/** True when the suppression has an expiry that is already in the past. */
export function isExpired(s, now = Date.now()) {
  return s?.expires_at != null && new Date(s.expires_at).getTime() < now
}

/** True when active but expiring within the next 7 days. */
export function isExpiringSoon(s, now = Date.now()) {
  if (s?.expires_at == null) return false
  const ms = new Date(s.expires_at).getTime() - now
  return ms > 0 && ms <= SOON_WINDOW_MS
}

/** Coarse status bucket: 'expired' | 'soon' | 'active'. */
export function suppressionStatus(s, now = Date.now()) {
  if (isExpired(s, now)) return 'expired'
  if (isExpiringSoon(s, now)) return 'soon'
  return 'active'
}
