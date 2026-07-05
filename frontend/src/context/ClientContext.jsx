import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../lib/apiBase'
import { normalizeIntegrations } from '../lib/engineClientPrefill'
import { filterClientsForOperatorRoster } from '../lib/clientRoster'

const defaultConfig = {
  enabled_engines: ['osint', 'asm', 'nexus_sovereign_swarm', 'bola_idor', 'llm_redteam', 'pki_tls', 'edr_evasion', 'saml_attack', 'zero_day_prediction'],
  roe_mode: 'safe_proofs',
  stealth_level: 50,
  auto_harvest: true,
  industrial_ot_enabled: false,
}

const ClientContext = createContext(null)

function parseConfigFromResponse(data) {
  if (!data || typeof data !== 'object') return defaultConfig
  const engines = Array.isArray(data.enabled_engines) ? data.enabled_engines : defaultConfig.enabled_engines
  const roe = data.roe_mode === 'weaponized_god_mode' ? 'weaponized_god_mode' : 'safe_proofs'
  const stealth = typeof data.stealth_level === 'number' ? Math.max(0, Math.min(100, data.stealth_level)) : defaultConfig.stealth_level
  const autoHarvest = typeof data.auto_harvest === 'boolean' ? data.auto_harvest : defaultConfig.auto_harvest
  const industrialOt = typeof data.industrial_ot_enabled === 'boolean' ? data.industrial_ot_enabled : defaultConfig.industrial_ot_enabled
  return { enabled_engines: engines, roe_mode: roe, stealth_level: stealth, auto_harvest: autoHarvest, industrial_ot_enabled: industrialOt }
}

export function ClientProvider({ children }) {
  const [clients, setClients] = useState([])
  const [clientsError, setClientsError] = useState(null)
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [clientConfig, setClientConfigState] = useState(defaultConfig)
  const [configLoading, setConfigLoading] = useState(false)
  const [configError, setConfigError] = useState(null)
  const [poeJobId, setPoeJobId] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const [integrationsLoading, setIntegrationsLoading] = useState(false)
  const selectedClientIdRef = useRef(null)

  selectedClientIdRef.current = selectedClientId

  const dismissConfigError = useCallback(() => setConfigError(null), [])
  const dismissClientsError = useCallback(() => setClientsError(null), [])

  const refreshClients = useCallback(async () => {
    try {
      const r = await apiFetch('/api/clients')
      if (r.ok) {
        const data = await r.json()
        if (Array.isArray(data)) {
          setClients(filterClientsForOperatorRoster(data))
          setClientsError(null)
        } else {
          setClients([])
          setClientsError('Unexpected response from /api/clients (expected a list).')
        }
      } else {
        setClients([])
        setClientsError(await formatApiErrorResponse(r))
      }
    } catch (e) {
      setClients([])
      setClientsError(e?.message || 'Network error')
    }
  }, [])

  const refreshConfig = useCallback(async (clientId) => {
    if (clientId == null) {
      setClientConfigState(defaultConfig)
      setConfigError(null)
      return
    }
    setConfigLoading(true)
    setConfigError(null)
    try {
      const r = await apiFetch(`/api/clients/${clientId}/config`)
      if (r.ok) {
        const data = await r.json()
        if (selectedClientIdRef.current === clientId) {
          setClientConfigState(parseConfigFromResponse(data))
        }
      } else {
        const msg = await formatApiErrorResponse(r)
        if (selectedClientIdRef.current === clientId) {
          setConfigError(msg)
          setClientConfigState(defaultConfig)
        }
      }
    } catch (e) {
      if (selectedClientIdRef.current === clientId) {
        setConfigError(e?.message || 'Network error')
        setClientConfigState(defaultConfig)
      }
    } finally {
      setConfigLoading(false)
    }
  }, [])

  const refreshIntegrations = useCallback(async (clientId) => {
    if (clientId == null) {
      setClientIntegrations(null)
      return null
    }
    setIntegrationsLoading(true)
    try {
      const r = await apiFetch(`/api/clients/${clientId}/integrations`)
      if (r.ok) {
        const data = normalizeIntegrations(await r.json())
        if (selectedClientIdRef.current === clientId) {
          setClientIntegrations(data)
        }
        return data
      }
      if (selectedClientIdRef.current === clientId) {
        setClientIntegrations(null)
      }
      return null
    } catch {
      if (selectedClientIdRef.current === clientId) {
        setClientIntegrations(null)
      }
      return null
    } finally {
      setIntegrationsLoading(false)
    }
  }, [])

  useEffect(() => {
    refreshClients()
  }, [refreshClients])

  useEffect(() => {
    setPoeJobId(null)
    refreshConfig(selectedClientId)
    refreshIntegrations(selectedClientId)
  }, [selectedClientId, refreshConfig, refreshIntegrations])

  const patchConfig = useCallback(async (clientId, patch) => {
    if (clientId == null) return false
    setConfigError(null)
    try {
      const r = await apiFetch(`/api/clients/${clientId}/config`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      })
      if (r.ok) {
        const data = await r.json()
        if (data.config && selectedClientIdRef.current === clientId) {
          setClientConfigState(parseConfigFromResponse(data.config))
        }
        return true
      }
      if (r.status === 409) {
        const data = await r.json().catch(() => null)
        if (data?.error_code === 'roe_approval_required') {
          const reqId = data.request_id ? `Request #${data.request_id}` : 'Request created'
          setConfigError(`Weaponized ROE requires 2 admin approvals. ${reqId}. Go to /roe-approvals to approve.`)
          return false
        }
      }
      setConfigError(await formatApiErrorResponse(r))
    } catch (e) {
      setConfigError(e?.message || 'Network error')
    }
    return false
  }, [])

  const selectedClient = clients.find((c) => String(c.id) === String(selectedClientId))

  const value = {
    clients,
    clientsError,
    dismissClientsError,
    refreshClients,
    selectedClientId,
    setSelectedClientId,
    selectedClient,
    clientConfig,
    setClientConfig: (patch) => patchConfig(selectedClientId, patch),
    patchConfig,
    refreshConfig: () => refreshConfig(selectedClientId),
    configLoading,
    configError,
    dismissConfigError,
    defaultConfig,
    poeJobId,
    setPoeJobId,
    clientIntegrations,
    integrationsLoading,
    refreshIntegrations: () => refreshIntegrations(selectedClientId),
  }

  return (
    <ClientContext.Provider value={value}>
      {children}
    </ClientContext.Provider>
  )
}

export function useClient() {
  const ctx = useContext(ClientContext)
  if (!ctx) throw new Error('useClient must be used within ClientProvider')
  return ctx
}
