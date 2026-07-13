/**
 * Closed Shadow DOM host — isolates forensic evidence from dashboard CSS/XSS.
 * Idempotent under React 18 Strict Mode (closed roots are invisible via .shadowRoot).
 */

/** @type {WeakMap<HTMLElement, ShadowRoot>} */
const shadowByHost = new WeakMap()

const HOST_FLAG = '__weissmanForensicShadow'

/**
 * @param {HTMLElement} host
 * @returns {ShadowRoot | null}
 */
function resolveShadow(host) {
  if (!host) return null
  const cached = shadowByHost.get(host)
  if (cached) return cached
  if (host[HOST_FLAG]) return host[HOST_FLAG]
  const open = host.shadowRoot
  if (open) {
    shadowByHost.set(host, open)
    return open
  }
  return null
}

/**
 * @param {HTMLElement} host
 * @param {string} html
 * @returns {ShadowRoot}
 */
export function mountForensicShadow(host, html) {
  let shadow = resolveShadow(host)
  if (!shadow) {
    try {
      shadow = host.attachShadow({ mode: 'closed' })
    } catch (err) {
      shadow = resolveShadow(host) || host[HOST_FLAG] || null
      if (!shadow) throw err
    }
    shadowByHost.set(host, shadow)
    try {
      host[HOST_FLAG] = shadow
    } catch {
      // frozen host — WeakMap is sufficient
    }
  }
  shadow.innerHTML = `
    <style>
      :host {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        flex-wrap: wrap;
        contain: content;
        isolation: isolate;
      }
      .forensic-badge {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 9px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid;
      }
      .forensic-tamper {
        color: #fca5a5;
        border-color: rgba(248,113,113,0.45);
        background: rgba(127,29,29,0.35);
        animation: pulse 1.2s ease-in-out infinite;
      }
      .forensic-verified {
        color: #6ee7b7;
        border-color: rgba(52,211,153,0.4);
        background: rgba(6,78,59,0.25);
      }
      .forensic-pending {
        color: #9ca3af;
        border-color: rgba(156,163,175,0.3);
        background: rgba(31,41,55,0.4);
      }
      .forensic-meta {
        font-size: 8px;
        color: #9ca3af;
        letter-spacing: 0.05em;
      }
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.65; }
      }
    </style>
    ${html}
  `
  return shadow
}

/**
 * Release shadow reference when React unmounts the host (Strict Mode safe).
 * Closed shadow roots stay on the element — do not clear HOST_FLAG or the WeakMap
 * entry, or a remount will throw "already hosts a shadow tree".
 * @param {HTMLElement} host
 */
export function unmountForensicShadow(_host) {
  // Intentionally no-op: closed ShadowRoot persists on the host across Strict Mode cycles.
}

/**
 * @param {object} p
 * @param {string} p.label
 * @param {string} p.tone - verified | tamper | pending
 * @param {string} [p.detail]
 */
export function forensicBadgeHtml({ label, tone, detail = '' }) {
  const cls =
    tone === 'tamper' ? 'forensic-badge forensic-tamper' : tone === 'verified' ? 'forensic-badge forensic-verified' : 'forensic-badge forensic-pending'
  const title = detail ? ` title="${escapeAttr(detail)}"` : ''
  return `<span class="${cls}"${title}>${escapeHtml(label)}</span>`
}

/**
 * @param {string} s
 */
export function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * @param {string} s
 */
export function escapeAttr(s) {
  return escapeHtml(s).replace(/'/g, '&#39;')
}
