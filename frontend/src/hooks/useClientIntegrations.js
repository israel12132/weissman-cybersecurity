import { useEffect, useState } from 'react'
import { useClient } from '../context/ClientContext'
import { fetchClientIntegrations } from '../lib/launchEngineScan'

/** Integrations for a client — global cache when matches sidebar selection. */
export function useClientIntegrations(clientId) {
  const {
    selectedClientId,
    clientIntegrations: globalIntegrations,
    integrationsLoading: globalLoading,
  } = useClient()

  const [localIntegrations, setLocalIntegrations] = useState(null)
  const [localLoading, setLocalLoading] = useState(false)

  const sameAsGlobal = clientId != null
    && clientId !== ''
    && String(clientId) === String(selectedClientId)

  useEffect(() => {
    if (!clientId) {
      setLocalIntegrations(null)
      return undefined
    }
    if (sameAsGlobal) {
      setLocalIntegrations(null)
      return undefined
    }
    let cancelled = false
    setLocalLoading(true)
    fetchClientIntegrations(clientId)
      .then((d) => { if (!cancelled) setLocalIntegrations(d) })
      .catch(() => { if (!cancelled) setLocalIntegrations(null) })
      .finally(() => { if (!cancelled) setLocalLoading(false) })
    return () => { cancelled = true }
  }, [clientId, sameAsGlobal])

  const integrations = sameAsGlobal ? globalIntegrations : localIntegrations
  const integrationsLoading = sameAsGlobal ? globalLoading : localLoading

  return { integrations, integrationsLoading }
}
