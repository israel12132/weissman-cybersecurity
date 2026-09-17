import { useEffect, useState } from 'react'
import { useClient } from '../context/ClientContext'
import { fetchClientIntegrations } from '../lib/launchEngineScan'

/** Integrations for a client — global cache when matches sidebar selection. */
export function useClientIntegrations(clientId) {
  const {
    selectedClientId,
    clientIntegrations: globalIntegrations,
    integrationsLoading: globalLoading,
    integrationsUnavailable: globalUnavailable,
  } = useClient()

  const [localIntegrations, setLocalIntegrations] = useState(null)
  const [localLoading, setLocalLoading] = useState(false)
  const [localUnavailable, setLocalUnavailable] = useState(false)

  const sameAsGlobal = clientId != null
    && clientId !== ''
    && String(clientId) === String(selectedClientId)

  useEffect(() => {
    if (!clientId) {
      setLocalIntegrations(null)
      setLocalUnavailable(false)
      return undefined
    }
    if (sameAsGlobal) {
      setLocalIntegrations(null)
      setLocalUnavailable(false)
      return undefined
    }
    let cancelled = false
    setLocalLoading(true)
    fetchClientIntegrations(clientId)
      .then((d) => {
        if (!cancelled) {
          // lib/apiBase.apiFetch does not throw on HTTP !ok; fetchClientIntegrations
          // resolves null. Treat that as leftover leftover-GET fail, not idle 0%.
          if (d == null) {
            setLocalIntegrations(null)
            setLocalUnavailable(true)
            return
          }
          setLocalIntegrations(d)
          setLocalUnavailable(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          // Leftover leftover-integrations stay catch-cleared (Billing-class).
          setLocalIntegrations(null)
          setLocalUnavailable(true)
        }
      })
      .finally(() => { if (!cancelled) setLocalLoading(false) })
    return () => { cancelled = true }
  }, [clientId, sameAsGlobal])

  const integrations = sameAsGlobal ? globalIntegrations : localIntegrations
  const integrationsLoading = sameAsGlobal ? globalLoading : localLoading
  const integrationsUnavailable = sameAsGlobal ? !!globalUnavailable : localUnavailable

  return { integrations, integrationsLoading, integrationsUnavailable }
}
