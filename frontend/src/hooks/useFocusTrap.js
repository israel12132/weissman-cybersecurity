import { useEffect } from 'react'

// Exclude tabindex="-1" everywhere (not just the generic [tabindex] clause) so
// roving-tabindex controls — e.g. the inactive tabs in an ARIA tablist — are
// never picked as the first/last boundary of the trap.
const FOCUSABLE =
  'button:not([disabled]):not([tabindex="-1"]), [href]:not([tabindex="-1"]), input:not([disabled]):not([tabindex="-1"]), select:not([disabled]):not([tabindex="-1"]), textarea:not([disabled]):not([tabindex="-1"]), [tabindex]:not([tabindex="-1"])'

/**
 * Trap Tab focus inside `containerRef` while `active` is true.
 * Focuses the first focusable element on activation, and restores focus to the
 * element that was focused before activation when the trap tears down (WCAG
 * 2.4.3 — focus order / no focus loss on overlay close).
 */
export default function useFocusTrap(containerRef, active) {
  useEffect(() => {
    if (!active || !containerRef.current) return undefined

    const root = containerRef.current
    const previouslyFocused = document.activeElement
    const getFocusable = () => [...root.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null)
    const focusables = getFocusable()
    focusables[0]?.focus()

    const onKeyDown = (e) => {
      if (e.key !== 'Tab') return
      const items = getFocusable()
      if (items.length === 0) return
      const first = items[0]
      const last = items[items.length - 1]
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault()
          last.focus()
        }
      } else if (document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (previouslyFocused && typeof previouslyFocused.focus === 'function' && document.contains(previouslyFocused)) {
        previouslyFocused.focus()
      }
    }
  }, [active, containerRef])
}
