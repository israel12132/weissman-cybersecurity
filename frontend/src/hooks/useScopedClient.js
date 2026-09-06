import { useCallback, useEffect, useMemo } from 'react'
import { useAuthOptional } from '../context/AuthContext'
import { useClient } from '../context/ClientContext'
import {
  boundClientId,
  filterVisibleClients,
  shouldHideClientPicker,
} from '../lib/clientScope'

function normalizeId(value) {
  if (value == null || value === '') return null
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? n : null
}

/**
 * Auto-bind + picker visibility for any engine/module that still keeps local
 * client state. When the session is scoped (or only one customer is visible)
 * the setter is forced onto that id and `hidePicker` is true.
 */
export function useScopedClient(value, onChange, clientsProp) {
  const auth = useAuthOptional()
  const session = auth?.session
  const ctx = useClient()
  const clients = Array.isArray(clientsProp) && clientsProp.length ? clientsProp : (ctx.clients || [])
  const visible = useMemo(
    () => filterVisibleClients(session, clients),
    [session, clients],
  )
  const hidePicker = shouldHideClientPicker(session, visible)
  const bound = boundClientId(session, visible, value ?? ctx.selectedClientId)

  useEffect(() => {
    if (!onChange || bound == null) return
    if (normalizeId(value) === normalizeId(bound)) return
    onChange(bound)
  }, [bound, onChange, value])

  const setClientId = useCallback(
    (next) => {
      if (hidePicker) {
        if (bound != null) onChange?.(bound)
        return
      }
      onChange?.(next)
    },
    [hidePicker, bound, onChange],
  )

  const selected = visible.find((c) => String(c.id) === String(bound ?? value)) || null

  return {
    clients: visible,
    clientId: bound ?? normalizeId(value),
    selectedClient: selected,
    hidePicker,
    setClientId,
    bound,
  }
}
