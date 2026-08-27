import { createContext, useContext, useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../utils/apiFetch'
import { destructiveHeaders } from '../utils/destructiveConfirm'
import { normalizeIntegrations } from '../lib/engineClientPrefill'
import { useAuthOptional } from './AuthContext'
import { assignedClientId, allowedClientIds, boundClientId, filterVisibleClients, shouldHideClientPicker } from '../lib/clientScope'

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
  const auth = useAuthOptional()
  const session = auth?.session
  const lockedClientId = assignedClientId(session)
  const allowedIds = useMemo(() => allowedClientIds(session), [session])

  const [clientsRaw, setClients] = useState([])
  const [clientsError, setClientsError] = useState(null)
  const [selectedClientId, setSelectedClientIdState] = useState(lockedClientId)
  const [clientConfig, setClientConfigState] = useState(defaultConfig)
  const [configLoading, setConfigLoading] = useState(false)
  const [configError, setConfigError] = useState(null)
  const [poeJobId, setPoeJobId] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const [integrationsLoading, setIntegrationsLoading] = useState(false)
  const selectedClientIdRef = useRef(null)
  // Monotonic request sequences: a response from a superseded selection must not
  // overwrite the current client's data, and — the bug this fixes — must not clear
  // the loading flag while the current request is still in flight.
  const configSeqRef = useRef(0)
  const integrationsSeqRef = useRef(0)

  selectedClientIdRef.current = selectedClientId

  const clients = useMemo(
    () => filterVisibleClients(session, clientsRaw),
    [session, clientsRaw],
  )
  const clientPickerHidden = shouldHideClientPicker(session, clients)
  // Locked identity = no picker. Staff with a single visible customer, and every
  // portal session with one assigned client, never switch tenants from the UI.
  const clientScopeLocked = clientPickerHidden

  const setSelectedClientId = useCallback(
    (id) => {
      if (clientPickerHidden) {
        setSelectedClientIdState(boundClientId(session, clients, id))
        return
      }
      if (allowedIds.length) {
        const n = Number(id)
        if (!Number.isFinite(n) || !allowedIds.includes(n)) return
      }
      setSelectedClientIdState(id)
    },
    [clientPickerHidden, session, clients, allowedIds],
  )

  useEffect(() => {
    const bound = boundClientId(session, clients, selectedClientId)
    if (bound != null && String(bound) !== String(selectedClientId)) {
      setSelectedClientIdState(bound)
    }
  }, [session, clients, selectedClientId])

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
    // Bump on every call — including the null branch — so switching away
    // invalidates any request already running for the previous selection.
    const seq = ++configSeqRef.current
    if (clientId == null) {
      setClientConfigState(defaultConfig)
      setConfigError(null)
      setConfigLoading(false)
      return
    }
    setConfigLoading(true)
    setConfigError(null)
    try {
      const data = await apiFetch(`/api/clients/${clientId}/config`)
      if (configSeqRef.current === seq) {
        setClientConfigState(parseConfigFromResponse(data))
      }
    } catch (e) {
      const msg = e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error')
      if (configSeqRef.current === seq) {
        setConfigError(msg)
        setClientConfigState(defaultConfig)
      }
    } finally {
      // Guard the loading reset with the same sequence: a stale response must not
      // settle the spinner while the current client's request is still loading.
      if (configSeqRef.current === seq) setConfigLoading(false)
    }
  }, [])

  const refreshIntegrations = useCallback(async (clientId) => {
    const seq = ++integrationsSeqRef.current
    if (clientId == null) {
      setClientIntegrations(null)
      setIntegrationsLoading(false)
      return null
    }
    setIntegrationsLoading(true)
    try {
      const data = normalizeIntegrations(await apiFetch(`/api/clients/${clientId}/integrations`))
      if (integrationsSeqRef.current === seq) {
        setClientIntegrations(data)
      }
      return data
    } catch {
      if (integrationsSeqRef.current === seq) {
        setClientIntegrations(null)
      }
      return null
    } finally {
      if (integrationsSeqRef.current === seq) setIntegrationsLoading(false)
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
        headers: patch?.industrial_ot_enabled === true ? destructiveHeaders() : {},
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
      if (e?.status === 403) {
        const data = e?.response ? await e.response.json().catch(() => null) : null
        if (data?.code === 'destructive_approval_required') {
          setConfigError(data.detail || 'Enabling industrial OT requires X-Weissman-Destructive-Confirm. Weissman never auto-enables OT.')
          return false
        }
      }
      setConfigError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error'))
    }
    return false
  }, [])

  const selectedClient = useMemo(
    () => clients.find((c) => String(c.id) === String(selectedClientId)),
    [clients, selectedClientId],
  )

  // Bind the selection-scoped helpers once per selection instead of allocating a
  // fresh closure on every render — ClientProvider sits under ProtectedOutlet and
  // re-renders on every navigation, and useClient has 41 consumers.
  const setClientConfig = useCallback(
    (patch) => patchConfig(selectedClientId, patch),
    [patchConfig, selectedClientId],
  )
  const refreshSelectedConfig = useCallback(
    () => refreshConfig(selectedClientId),
    [refreshConfig, selectedClientId],
  )
  const refreshSelectedIntegrations = useCallback(
    () => refreshIntegrations(selectedClientId),
    [refreshIntegrations, selectedClientId],
  )

  const value = useMemo(
    () => ({
      clients,
      clientsError,
      dismissClientsError,
      refreshClients,
      selectedClientId,
      setSelectedClientId,
      selectedClient,
      clientScopeLocked,
      clientPickerHidden,
      clientConfig,
      setClientConfig,
      patchConfig,
      refreshConfig: refreshSelectedConfig,
      configLoading,
      configError,
      dismissConfigError,
      defaultConfig,
      poeJobId,
      setPoeJobId,
      clientIntegrations,
      integrationsLoading,
      refreshIntegrations: refreshSelectedIntegrations,
    }),
    [
      clients,
      clientsError,
      dismissClientsError,
      refreshClients,
      selectedClientId,
      setSelectedClientId,
      selectedClient,
      clientScopeLocked,
      clientPickerHidden,
      clientConfig,
      setClientConfig,
      patchConfig,
      refreshSelectedConfig,
      configLoading,
      configError,
      dismissConfigError,
      poeJobId,
      clientIntegrations,
      integrationsLoading,
      refreshSelectedIntegrations,
    ],
  )

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
