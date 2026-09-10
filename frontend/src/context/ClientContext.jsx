import { createContext, useContext, useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../utils/apiFetch'
import { normalizeIntegrations } from '../lib/engineClientPrefill'
import { useAuthOptional } from './AuthContext'
import { assignedClientId, isClientUser } from '../lib/clientScope'

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
  const lockedClientId = isClientUser(session) ? assignedClientId(session) : null
  const clientScopeLocked = lockedClientId != null

  const [clients, setClients] = useState([])
  const [clientsError, setClientsError] = useState(null)
  const [selectedClientId, setSelectedClientIdState] = useState(lockedClientId)
  const [clientConfig, setClientConfigState] = useState(defaultConfig)
  const [configLoading, setConfigLoading] = useState(false)
  const [configError, setConfigError] = useState(null)
  const [poeJobId, setPoeJobId] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const [integrationsLoading, setIntegrationsLoading] = useState(false)
  const [roePending, setRoePending] = useState(null)
  const selectedClientIdRef = useRef(null)
  // Monotonic request sequences: a response from a superseded selection must not
  // overwrite the current client's data, and — the bug this fixes — must not clear
  // the loading flag while the current request is still in flight.
  const configSeqRef = useRef(0)
  const integrationsSeqRef = useRef(0)

  selectedClientIdRef.current = selectedClientId

  const setSelectedClientId = useCallback(
    (id) => {
      if (clientScopeLocked) {
        setSelectedClientIdState(lockedClientId)
        return
      }
      setSelectedClientIdState(id)
    },
    [clientScopeLocked, lockedClientId],
  )

  useEffect(() => {
    if (clientScopeLocked && lockedClientId != null) {
      setSelectedClientIdState(lockedClientId)
    }
  }, [clientScopeLocked, lockedClientId])

  const dismissConfigError = useCallback(() => {
    setConfigError(null)
    setRoePending(null)
  }, [])
  const dismissClientsError = useCallback(() => setClientsError(null), [])

  const refreshClients = useCallback(async () => {
    try {
      const data = await apiFetch('/api/clients')
      if (Array.isArray(data)) {
        setClients(data)
        setClientsError(null)
        if (
          !clientScopeLocked &&
          selectedClientIdRef.current == null &&
          data.length === 1 &&
          data[0]?.id != null
        ) {
          setSelectedClientIdState(data[0].id)
        }
      } else {
        setClients([])
        setClientsError('Unexpected response from /api/clients (expected a list).')
      }
    } catch (e) {
      setClients([])
      setClientsError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error'))
    }
  }, [clientScopeLocked])

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
      })
      if (data.config && selectedClientIdRef.current === clientId) {
        setClientConfigState(parseConfigFromResponse(data.config))
      }
      if (patch?.roe_mode) setRoePending(null)
      return true
    } catch (e) {
      if (e?.status === 409) {
        const data = e.body && typeof e.body === 'object'
          ? e.body
          : (e?.response ? await e.response.clone().json().catch(() => null) : null)
        if (data?.error_code === 'roe_approval_required') {
          const reqId = data.request_id ? `Request #${data.request_id}` : 'Request created'
          setRoePending({
            requestId: data.request_id,
            approvalsHave: Number(data.approvals_have) || 0,
            approvalsNeeded: Number(data.approvals_needed) || 2,
            adminUrl: data.admin_url || '/roe-approvals',
            detail: data.detail || '',
            clientId,
          })
          setConfigError(`Weaponized ROE requires 2 admin approvals. ${reqId}. Open /roe-approvals to approve as a distinct admin.`)
          return false
        }
      }
      setConfigError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || 'Network error'))
    }
    return false
  }, [])

  const submitRoeApproval = useCallback(async () => {
    if (!roePending?.requestId) return false
    try {
      await apiFetch(`/api/roe/override-requests/${roePending.requestId}/approve`, { method: 'POST' })
      const data = await apiFetch('/api/roe/override-requests?status=pending')
      const req = (data.requests || []).find((r) => Number(r.id) === Number(roePending.requestId))
      const have = req
        ? Number(!!req.first_approved_by_user_id) + Number(!!req.second_approved_by_user_id)
        : Math.min((roePending.approvalsHave || 0) + 1, 2)
      setRoePending((prev) => (prev ? { ...prev, approvalsHave: have } : prev))
      setConfigError(
        have >= 2
          ? 'Two-admin ROE approval complete. Re-apply weaponized mode.'
          : 'Your approval was recorded. A second distinct admin must sign in and approve at /roe-approvals.',
      )
      return true
    } catch (e) {
      const data = e.body && typeof e.body === 'object' ? e.body : null
      setConfigError(data?.detail || e?.message || 'ROE approval failed')
      return false
    }
  }, [roePending])

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
      roePending,
      submitRoeApproval,
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
      roePending,
      submitRoeApproval,
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
