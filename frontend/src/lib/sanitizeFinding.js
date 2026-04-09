/**
 * Defense-in-depth for API-sourced strings shown as text (React escapes markup;
 * this strips NULs, caps size, and removes simple HTML-like tags).
 */
export function sanitizeFindingPlainText(value, maxLen = 256_000) {
  if (value == null) return ''
  let s = typeof value === 'string' ? value : String(value)
  s = s.replace(/\0/g, '')
  if (s.length > maxLen) {
    s = `${s.slice(0, maxLen)}\n… [truncated]`
  }
  return s.replace(/<\/?[a-zA-Z][a-zA-Z0-9:-]{0,60}(\s[^>]*)?>/g, '')
}
