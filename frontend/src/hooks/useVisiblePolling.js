import { useEffect, useRef } from 'react'

/**
 * Run `fn` on a fixed interval, but skip ticks while the document is hidden
 * (background tab) and while `paused` is true. Saves needless network/battery
 * for a feed nobody is looking at, and resumes cleanly on return.
 *
 * `fn` is always called through a ref, so an inline callback that changes
 * identity every render does NOT restart the interval — only `intervalMs` and
 * `paused` do.
 *
 * @param {() => void} fn        work to run each visible, unpaused tick
 * @param {number} intervalMs    tick period in ms (<= 0 disables the timer)
 * @param {{paused?: boolean}} [opts]
 */
export function useVisiblePolling(fn, intervalMs, { paused = false } = {}) {
  const fnRef = useRef(fn)
  useEffect(() => {
    fnRef.current = fn
  }, [fn])

  useEffect(() => {
    if (paused || !intervalMs || intervalMs <= 0) return undefined
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return
      fnRef.current?.()
    }, intervalMs)
    return () => clearInterval(id)
  }, [intervalMs, paused])
}
