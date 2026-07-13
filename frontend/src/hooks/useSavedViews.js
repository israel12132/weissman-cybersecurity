import { useCallback, useState } from 'react'

/**
 * Per-table saved views (named filter/sort snapshots) persisted to localStorage.
 * Client-side only — no server round-trip, no fabricated data. The `state` blob
 * is opaque to the hook: the consuming page decides what to snapshot/restore.
 */

const MAX_VIEWS = 20

export function readViews(storageKey) {
  try {
    const raw = JSON.parse(localStorage.getItem(storageKey) || '[]')
    if (!Array.isArray(raw)) return []
    return raw.filter((v) => v && typeof v.id === 'string' && typeof v.name === 'string')
  } catch {
    return []
  }
}

function persist(storageKey, views) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(views))
  } catch {
    /* storage may be unavailable / full */
  }
}

/** Pure: insert-or-replace a view by (case-insensitive) name, newest last. */
export function upsertView(views, name, state, id) {
  const trimmed = String(name || '').trim()
  if (!trimmed) return views
  const key = trimmed.toLowerCase()
  const without = views.filter((v) => v.name.trim().toLowerCase() !== key)
  return [...without, { id, name: trimmed, state }].slice(-MAX_VIEWS)
}

/** Pure: remove a view by id. */
export function removeView(views, id) {
  return views.filter((v) => v.id !== id)
}

function newId() {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID()
    }
  } catch {
    /* fall through */
  }
  return `v_${Date.now()}_${Math.round(Math.random() * 1e6)}`
}

export function useSavedViews(storageKey) {
  const [views, setViews] = useState(() => readViews(storageKey))

  const saveView = useCallback((name, state) => {
    setViews((prev) => {
      const next = upsertView(prev, name, state, newId())
      persist(storageKey, next)
      return next
    })
  }, [storageKey])

  const deleteView = useCallback((id) => {
    setViews((prev) => {
      const next = removeView(prev, id)
      persist(storageKey, next)
      return next
    })
  }, [storageKey])

  return { views, saveView, deleteView }
}
