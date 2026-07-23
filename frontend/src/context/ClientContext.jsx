import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../utils/apiFetch'
import { normalizeIntegrations } from '../lib/engineClientPrefill'

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
      const data = await apiFetch('/api/clients')
      if (Array.isArray(data)) {
        setClients(data)
        setClientsError(null)
      } else {
        setClients([])
        setClientsError('Unexpected response from /api/clients (expected a list).')
      }
    } catch (e) {
      setClients([])
      setClientsError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error'))
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
      const data = await apiFetch(`/api/clients/${clientId}/config`)
      if (selectedClientIdRef.current === clientId) {
        setClientConfigState(parseConfigFromResponse(data))
      }
    } catch (e) {
      const msg = e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error')
      if (selectedClientIdRef.current === clientId) {
        setConfigError(msg)
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
      const data = normalizeIntegrations(await apiFetch(`/api/clients/${clientId}/integrations`))
      if (selectedClientIdRef.current === clientId) {
        setClientIntegrations(data)
      }
      return data
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
      const data = await apiFetch(`/api/clients/${clientId}/config`, {
        method: 'PATCH',
        body: patch,
      })
      if (data.config && selectedClientIdRef.current === clientId) {
        setClientConfigState(parseConfigFromResponse(data.config))
      }
      return true
    } catch (e) {
      if (e?.status === 409) {
        const data = e?.response ? await e.response.json().catch(() => null) : null
        if (data?.error_code === 'roe_approval_required') {
          const reqId = data.request_id ? `Request #${data.request_id}` : 'Request created'
          setConfigError(`Weaponized ROE requires 2 admin approvals. ${reqId}. Go to /roe-approvals to approve.`)
          return false
        }
      }
      setConfigError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error'))
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
