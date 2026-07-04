import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'

const EngineC2BoundaryContext = createContext(false)
const EngineC2ControlContext = createContext(null)

/**
 * Marks descendants as legally inside morphing engine C2 chrome.
 * Rendering engine weapons outside this boundary is a hard error.
 */
export function EngineC2Boundary({ children }) {
  return (
    <EngineC2BoundaryContext.Provider value={true}>
      {children}
    </EngineC2BoundaryContext.Provider>
  )
}

export function useInsideEngineC2() {
  const inside = useContext(EngineC2BoundaryContext)
  if (!inside) {
    throw new Error(
      'ENGINE C2 UI BYPASS: tool surface rendered outside MorphingEngineChrome. ' +
        'Wrap with withMorphingEngineChrome() or PageShell.',
    )
  }
}

export function EngineC2ControlProvider({ children, killSwitchEnabled = false }) {
  const abortRef = useRef(null)
  const [killed, setKilled] = useState(false)
  const [killReason, setKillReason] = useState('')

  const registerAbort = useCallback((controller) => {
    abortRef.current = controller
  }, [])

  const triggerKill = useCallback((reason = 'operator_kill_switch') => {
    setKilled(true)
    setKillReason(reason)
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
  }, [])

  const resetKill = useCallback(() => {
    setKilled(false)
    setKillReason('')
    abortRef.current = null
  }, [])

  const value = useMemo(
    () => ({
      killSwitchEnabled,
      killed,
      killReason,
      registerAbort,
      triggerKill,
      resetKill,
    }),
    [killSwitchEnabled, killed, killReason, registerAbort, triggerKill, resetKill],
  )

  return (
    <EngineC2ControlContext.Provider value={value}>
      {children}
    </EngineC2ControlContext.Provider>
  )
}

export function useEngineC2Control() {
  const ctx = useContext(EngineC2ControlContext)
  if (!ctx) {
    return {
      killSwitchEnabled: false,
      killed: false,
      killReason: '',
      registerAbort: () => {},
      triggerKill: () => {},
      resetKill: () => {},
    }
  }
  return ctx
}

/** Returns an AbortSignal wired to the C2 kill-switch when enabled. */
export function useC2AbortSignal() {
  const { registerAbort, killed } = useEngineC2Control()
  const controllerRef = useRef(null)

  if (!controllerRef.current || controllerRef.current.signal.aborted) {
    controllerRef.current = new AbortController()
    registerAbort(controllerRef.current)
  }

  return { signal: controllerRef.current.signal, killed }
}
