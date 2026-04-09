import { useCallback, useRef, useEffect } from 'react'

function useAudioContext() {
  const ctxRef = useRef(null)
  useEffect(() => {
    if (typeof window === 'undefined') return
    ctxRef.current = new (window.AudioContext || window.webkitAudioContext)()
    return () => {
      if (ctxRef.current) ctxRef.current.close()
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
    if (!ctx) return
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
    } catch (_) {}
  }, [])

  const playBlip = useCallback(() => {
    const ctx = audioRef.current
    if (!ctx) return
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
    } catch (_) {}
  }, [])

  const startAlarmHum = useCallback(() => {
    const ctx = audioRef.current
    if (!ctx) return
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
    } catch (_) {}
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
    } catch (_) {}
  }, [])

  return { playZoom, playBlip, startAlarmHum, stopAlarmHum }
}
