import { useCallback, useRef, useEffect } from 'react'

function useAudioContext() {
  const ctxRef = useRef(null)
  useEffect(() => {
    if (typeof window === 'undefined') return undefined
    // Guard construction: where neither global exists, `new undefined()` throws a
    // TypeError from inside the effect and blanks the route.
    const Ctor = window.AudioContext || window.webkitAudioContext
    if (!Ctor) return undefined
    let ctx
    try {
      ctx = new Ctor()
    } catch {
      return undefined
    }
    ctxRef.current = ctx
    // Autoplay policy creates the context `suspended` until a user gesture; without
    // a resume every scheduled oscillator is silent. Unlock on the first interaction.
    const unlock = () => {
      // resume() can reject if the context was closed between the gesture and this
      // call (fast unmount) — nothing to recover, so swallow to undefined.
      if (ctx.state === 'suspended') ctx.resume().catch(() => undefined)
    }
    window.addEventListener('pointerdown', unlock)
    window.addEventListener('keydown', unlock)
    return () => {
      window.removeEventListener('pointerdown', unlock)
      window.removeEventListener('keydown', unlock)
      try {
        ctx.close()
      } catch {
        /* already closed / unsupported — non-fatal */
      }
      ctxRef.current = null
    }
  }, [])
  return ctxRef
}

export function useWarRoomSound() {
  const audioRef = useAudioContext()
  const humGainRef = useRef(null)
  const humOscRef = useRef(null)

  const playZoom = useCallback(() => {
    const ctx = audioRef.current
    if (!ctx || ctx.state !== 'running') return
    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.frequency.setValueAtTime(400, now)
      osc.frequency.exponentialRampToValueAtTime(1200, now + 0.12)
      osc.type = 'sine'
      gain.gain.setValueAtTime(0.08, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2)
      osc.start(now)
      osc.stop(now + 0.2)
    } catch (_) { /* best-effort; non-fatal */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const playBlip = useCallback(() => {
    const ctx = audioRef.current
    if (!ctx || ctx.state !== 'running') return
    try {
      const now = ctx.currentTime
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.frequency.setValueAtTime(800, now)
      osc.type = 'sine'
      gain.gain.setValueAtTime(0.06, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08)
      osc.start(now)
      osc.stop(now + 0.08)
    } catch (_) { /* best-effort; non-fatal */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const startAlarmHum = useCallback(() => {
    const ctx = audioRef.current
    if (!ctx || ctx.state !== 'running') return
    try {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.frequency.setValueAtTime(55, ctx.currentTime)
      osc.type = 'sine'
      gain.gain.setValueAtTime(0.03, ctx.currentTime)
      osc.start(ctx.currentTime)
      humOscRef.current = osc
      humGainRef.current = gain
    } catch (_) { /* best-effort; non-fatal */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const stopAlarmHum = useCallback(() => {
    try {
      if (humOscRef.current && humGainRef.current) {
        const ctx = audioRef.current
        if (ctx) {
          humGainRef.current.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.1)
          humOscRef.current.stop(ctx.currentTime + 0.1)
        }
        humOscRef.current = null
        humGainRef.current = null
      }
    } catch (_) { /* best-effort; non-fatal */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return { playZoom, playBlip, startAlarmHum, stopAlarmHum }
}
