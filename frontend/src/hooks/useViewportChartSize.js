import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * Chart dimensions that stay inside the viewport (phone + desktop).
 * Prefer {@link useContainerChartSize} for elements inside a grid/flex column — viewport width is too wide and causes horizontal overflow.
 */
export function useViewportChartSize(maxWidth = 720, heightSm = 140, heightLg = 200) {
  const [size, setSize] = useState({ width: Math.min(maxWidth, 360), height: heightSm })

  useEffect(() => {
    const update = () => {
      const vw = typeof window !== 'undefined' ? window.innerWidth : 360
      const padding = vw < 640 ? 24 : 48
      const w = Math.max(260, Math.min(maxWidth, vw - padding))
      const h = vw < 640 ? heightSm : heightLg
      setSize({ width: w, height: h })
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [maxWidth, heightSm, heightLg])

  return size
}

/**
 * Measures a DOM node so charts (e.g. SVG) never exceed their column — fixes page-wide horizontal scroll.
 * Uses a callback ref so the first layout after mount is observed (object refs + useEffect miss the first frame).
 */
export function useContainerChartSize(minWidth = 120) {
  const roRef = useRef(null)
  const [size, setSize] = useState({ width: 320, height: 160 })

  const setContainerRef = useCallback((el) => {
    if (roRef.current) {
      roRef.current.disconnect()
      roRef.current = null
    }
    if (!el) return

    const apply = (w, h) => {
      const wi = Math.max(minWidth, Math.floor(w))
      const hi = Math.max(80, Math.floor(h))
      setSize((prev) => (prev.width === wi && prev.height === hi ? prev : { width: wi, height: hi }))
    }

    const cr = el.getBoundingClientRect()
    apply(cr.width, cr.height)

    if (typeof ResizeObserver === 'undefined') {
      const onWin = () => {
        const r = el.getBoundingClientRect()
        apply(r.width, r.height)
      }
      window.addEventListener('resize', onWin)
      roRef.current = { disconnect: () => window.removeEventListener('resize', onWin) }
      return
    }

    const ro = new ResizeObserver((entries) => {
      const entry = entries[0]
      if (!entry) return
      apply(entry.contentRect.width, entry.contentRect.height)
    })
    ro.observe(el)
    roRef.current = ro
  }, [minWidth])

  useEffect(
    () => () => {
      if (roRef.current && typeof roRef.current.disconnect === 'function') {
        roRef.current.disconnect()
      }
    },
    [],
  )

  return [setContainerRef, size]
}
