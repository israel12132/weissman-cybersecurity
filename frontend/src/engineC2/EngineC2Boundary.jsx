import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

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
        'Wrap the page in PageShell (which applies MorphingEngineChrome).',
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
    // Don't null the ref here — the consumer's effect re-registers a fresh
    // controller on the killed→false transition, so a second Emergency Stop
    // after a Reset still has a live controller to abort.
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
  if (!controllerRef.current) {
    controllerRef.current = new AbortController()
  }

  // Register (and re-register) the controller with the provider from an effect
  // so we never mutate the shared abort ref during render. After a kill→reset
  // cycle the previous controller is already aborted; swap in a fresh one so the
  // NEXT Emergency Stop still aborts in-flight work.
  useEffect(() => {
    if (controllerRef.current.signal.aborted) {
      controllerRef.current = new AbortController()
    }
    registerAbort(controllerRef.current)
    return () => registerAbort(null)
  }, [killed, registerAbort])

  return { signal: controllerRef.current.signal, killed }
}
