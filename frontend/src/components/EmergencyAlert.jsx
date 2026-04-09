import { useEffect, useState } from 'react'

const SCROLL_DURATION_MS = 8000

/**
 * Full-screen horizontal scrolling banner. Slides right-to-left exactly twice, then disappears.
 * High-contrast Neon Red background, white monospace text, glowing borders.
 * Content: WARNING: [ACTION/FINDING TYPE] - [EXACT DETAILS]
 */
export default function EmergencyAlert({ message, onComplete }) {
  const [visible, setVisible] = useState(!!message)

  useEffect(() => {
    if (!message) {
      setVisible(false)
      return
    }
    setVisible(true)
    const totalMs = SCROLL_DURATION_MS
    const t = setTimeout(() => {
      setVisible(false)
      onComplete?.()
    }, totalMs)
    return () => clearTimeout(t)
  }, [message, onComplete])

  if (!visible || !message) return null

  return (
    <div className="emergency-alert-overlay" role="alert" aria-live="assertive">
      <div className="emergency-alert-banner">
        <span className="emergency-alert-text">{message}</span>
      </div>
    </div>
  )
}
