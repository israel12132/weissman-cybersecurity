import React, { createContext, useCallback, useContext, useMemo, useState } from 'react'

const EngineHubContext = createContext(null)

/** Tracks active command-center client + shared scan params for PageShell / postScan. */
export function EngineHubProvider({ children }) {
  const [hubClientId, setHubClientIdState] = useState(null)
  const [hubEngineId, setHubEngineIdState] = useState(null)
  const [hubExtraParams, setHubExtraParamsState] = useState({})

  const setHubClientId = useCallback((id) => {
    const next = id == null || id === '' ? null : String(id)
    setHubClientIdState((prev) => (prev === next ? prev : next))
  }, [])

  const setHubEngineId = useCallback((id) => {
    const next = id == null || id === '' ? null : String(id)
    setHubEngineIdState((prev) => (prev === next ? prev : next))
  }, [])

  const setHubExtraParams = useCallback((params) => {
    setHubExtraParamsState(params && typeof params === 'object' ? params : {})
  }, [])

  const value = useMemo(
    () => ({
      hubClientId,
      hubEngineId,
      hubExtraParams,
      setHubClientId,
      setHubEngineId,
      setHubExtraParams,
    }),
    [hubClientId, hubEngineId, hubExtraParams, setHubClientId, setHubEngineId, setHubExtraParams],
  )

  return (
    <EngineHubContext.Provider value={value}>
      {children}
    </EngineHubContext.Provider>
  )
}

export function useEngineHub() {
  const ctx = useContext(EngineHubContext)
  if (!ctx) {
    return {
      hubClientId: null,
      hubEngineId: null,
      hubExtraParams: {},
      setHubClientId: () => {},
      setHubEngineId: () => {},
      setHubExtraParams: () => {},
    }
  }
  return ctx
}

/** Register page clientId while mounted (used by useCommandCenterScan). */
export function useRegisterHubClient(clientId) {
  const { setHubClientId } = useEngineHub()
  React.useEffect(() => {
    if (clientId == null || clientId === '') {
      setHubClientId(null)
      return () => setHubClientId(null)
    }
    setHubClientId(clientId)
    return () => setHubClientId(null)
  }, [clientId, setHubClientId])
}
