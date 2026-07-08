/**
 * Self-healing SSE client over fetch + ReadableStream.
 * Auth via Authorization: Bearer and HttpOnly cookies — never query-string secrets.
 */

import { apiUrl, authHeaders, getStoredAccessToken, setStoredAccessToken } from './apiBase'

export const SSE_CONNECTING = 0
export const SSE_OPEN = 1
export const SSE_CLOSED = 2

const DEFAULT_MIN_BACKOFF_MS = 1000
const DEFAULT_MAX_BACKOFF_MS = 30_000
const BACKOFF_FACTOR = 1.5

async function refreshAccessToken() {
  try {
    const r = await fetch(apiUrl('/api/auth/refresh'), {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!r.ok) return false
    const data = await r.json().catch(() => ({}))
    if (data.ok && data.access_token) {
      setStoredAccessToken(data.access_token)
      return true
    }
    return false
  } catch {
    return false
  }
}

function resolveUrl(pathOrUrl) {
  const s = String(pathOrUrl || '')
  if (s.startsWith('http://') || s.startsWith('https://')) return s
  return apiUrl(s.startsWith('/') ? s : `/${s}`)
}

function buildAuthHeaders(lastEventId) {
  const headers = new Headers({ Accept: 'text/event-stream', 'Cache-Control': 'no-cache' })
  const ah = authHeaders()
  if (ah.Authorization) headers.set('Authorization', ah.Authorization)
  if (lastEventId) headers.set('Last-Event-ID', lastEventId)
  return headers
}

/**
 * Parse SSE frames from a byte stream (RFC 8895 subset).
 */
async function consumeSseStream(reader, decoder, onFrame, signal) {
  let buffer = ''
  while (!signal.aborted) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const block = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      if (block.trim()) onFrame(parseSseBlock(block))
    }
  }
}

function parseSseBlock(block) {
  let eventType = 'message'
  const dataLines = []
  let id = null
  let retry = null
  for (const line of block.split('\n')) {
    if (!line || line.startsWith(':')) continue
    const colon = line.indexOf(':')
    const field = colon === -1 ? line : line.slice(0, colon)
    let value = colon === -1 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    switch (field) {
      case 'event':
        eventType = value
        break
      case 'data':
        dataLines.push(value)
        break
      case 'id':
        id = value
        break
      case 'retry':
        retry = Number.parseInt(value, 10)
        break
      default:
        break
    }
  }
  return { eventType, data: dataLines.join('\n'), id, retry }
}

/**
 * Resilient SSE connection — API-compatible with EventSource where practical.
 *
 * @param {string} pathOrUrl - API path or absolute URL (no auth in query string)
 * @param {object} [options]
 * @param {() => string} [options.getReconnectUrl] - dynamic URL for cursor-based resume
 * @param {number} [options.minBackoffMs]
 * @param {number} [options.maxBackoffMs]
 */
export function openSseStream(pathOrUrl, options = {}) {
  return new SseStream(pathOrUrl, options)
}

export class SseStream {
  constructor(pathOrUrl, options = {}) {
    this._initialUrl = resolveUrl(pathOrUrl)
    this.url = this._initialUrl
    this._getReconnectUrl = options.getReconnectUrl
    this._minBackoff = options.minBackoffMs ?? DEFAULT_MIN_BACKOFF_MS
    this._maxBackoff = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
    this.readyState = SSE_CONNECTING
    this._lastEventId = ''
    this._listeners = new Map()
    this._onopen = null
    this._onmessage = null
    this._onerror = null
    this._abort = null
    this._closed = false
    this._backoffMs = this._minBackoff
    this._reconnectTimer = null
    this._connect()
  }

  get onopen() {
    return this._onopen
  }
  set onopen(fn) {
    this._onopen = fn
  }

  get onmessage() {
    return this._onmessage
  }
  set onmessage(fn) {
    this._onmessage = fn
  }

  get onerror() {
    return this._onerror
  }
  set onerror(fn) {
    this._onerror = fn
  }

  addEventListener(type, handler) {
    if (typeof handler !== 'function') return
    if (!this._listeners.has(type)) this._listeners.set(type, new Set())
    this._listeners.get(type).add(handler)
  }

  removeEventListener(type, handler) {
    this._listeners.get(type)?.delete(handler)
  }

  close() {
    this._closed = true
    this.readyState = SSE_CLOSED
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer)
      this._reconnectTimer = null
    }
    if (this._abort) {
      this._abort.abort()
      this._abort = null
    }
  }

  _dispatch(type, event) {
    const handlers = this._listeners.get(type)
    if (handlers) {
      for (const fn of handlers) {
        try {
          fn(event)
        } catch {
          /* listener fault isolation */
        }
      }
    }
    if (type === 'open' && this._onopen) this._onopen(event)
    if (type === 'message' && this._onmessage) this._onmessage(event)
    if (type === 'error' && this._onerror) this._onerror(event)
  }

  _scheduleReconnect() {
    if (this._closed) return
    this.readyState = SSE_CONNECTING
    const delay = this._backoffMs
    this._backoffMs = Math.min(this._backoffMs * BACKOFF_FACTOR, this._maxBackoff)
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null
      this._connect()
    }, delay)
  }

  async _connect() {
    if (this._closed) return
    if (this._abort) this._abort.abort()
    const controller = new AbortController()
    this._abort = controller

    const url = this._getReconnectUrl ? resolveUrl(this._getReconnectUrl()) : this._initialUrl
    this.url = url

    let response
    try {
      response = await fetch(url, {
        method: 'GET',
        credentials: 'include',
        headers: buildAuthHeaders(this._lastEventId),
        signal: controller.signal,
        cache: 'no-store',
      })
    } catch (err) {
      if (controller.signal.aborted || this._closed) return
      this._dispatch('error', err)
      this._scheduleReconnect()
      return
    }

    if (response.status === 401 && getStoredAccessToken()) {
      // Refresh at most once per connection cycle; if still unauthorized, fall through to the
      // backoff-scheduled reconnect below instead of recursing into a tight
      // 401 → refresh → reconnect loop that would hammer the backend.
      if (!this._refreshedThisCycle) {
        this._refreshedThisCycle = true
        const refreshed = await refreshAccessToken()
        if (refreshed && !this._closed) {
          this._connect()
          return
        }
      }
      if (this._closed) return
      this._dispatch('error', new Error('SSE unauthorized'))
      this._scheduleReconnect()
      return
    }

    if (!response.ok || !response.body) {
      if (this._closed) return
      this._dispatch('error', new Error(`SSE HTTP ${response.status}`))
      this._scheduleReconnect()
      return
    }

    this.readyState = SSE_OPEN
    this._backoffMs = this._minBackoff
    this._refreshedThisCycle = false // a healthy connection re-arms the single-refresh guard
    this._dispatch('open', { type: 'open' })

    const reader = response.body.getReader()
    const decoder = new TextDecoder()

    try {
      await consumeSseStream(
        reader,
        decoder,
        (frame) => {
          if (frame.id) this._lastEventId = frame.id
          if (Number.isFinite(frame.retry) && frame.retry > 0) {
            this._minBackoff = frame.retry
          }
          const ev = { type: frame.eventType, data: frame.data, lastEventId: frame.id || this._lastEventId }
          if (frame.eventType === 'message') {
            this._dispatch('message', ev)
          } else {
            this._dispatch(frame.eventType, ev)
          }
        },
        controller.signal,
      )
    } catch (err) {
      if (controller.signal.aborted || this._closed) return
      this._dispatch('error', err)
    } finally {
      try {
        reader.releaseLock()
      } catch {
        /* already released */
      }
    }

    if (!this._closed) {
      this._dispatch('error', new Error('SSE stream ended'))
      this._scheduleReconnect()
    }
  }
}
