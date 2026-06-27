import { useCallback, useEffect, useState } from 'react'
import { prefillParamsForEngine } from '../lib/engineClientPrefill'
import { clientPrimaryTargetUrl, resolveClient } from '../lib/clientTarget'
import { useSyncHubScanParams } from './useLaunchEngineScan'
import { useClientIntegrations } from './useClientIntegrations'

/**
 * Local param state for rich hub UIs — prefill from integrations + sync to EngineHubContext.
 * Use with PageShell hideHubParams when the page renders its own parameter form.
 */
export function useHubLocalScanParams(engineId, defaultParams, clientId) {
  const { integrations } = useClientIntegrations(clientId)
  const [params, setParams] = useState(defaultParams)

  useEffect(() => {
    if (!engineId || !integrations) return
    setParams((prev) => prefillParamsForEngine(engineId, integrations, prev))
  }, [engineId, integrations])

  const setField = useCallback((key, value) => {
    setParams((prev) => ({ ...prev, [key]: value }))
  }, [])

  useSyncHubScanParams(engineId, params)

  return { params, setParams, setField, integrations }
}

/** Prefill target field from client primary domain when client is selected. */
export function useClientTargetPrefill(clientId, clients, setTarget, {
  onlyIfEmpty = true,
  respectTouched = false,
  targetTouched = false,
} = {}) {
  useEffect(() => {
    if (respectTouched && targetTouched) return
    if (!clientId || typeof setTarget !== 'function') return
    const client = resolveClient(clientId, clients)
    const url = clientPrimaryTargetUrl(client)
    if (!url) return
    if (onlyIfEmpty) setTarget((prev) => prev || url)
    else setTarget(url)
  }, [clientId, clients, setTarget, onlyIfEmpty, respectTouched, targetTouched])
}

/** Prefill existing params state when client integrations load (identity / spray / kerberos hubs). */
export function useIntegrationsPrefill(engineId, clientId, setParams) {
  const { integrations } = useClientIntegrations(clientId)

  useEffect(() => {
    if (!engineId || !integrations || typeof setParams !== 'function') return
    setParams((prev) => prefillParamsForEngine(engineId, integrations, prev))
  }, [engineId, integrations, setParams])
}
