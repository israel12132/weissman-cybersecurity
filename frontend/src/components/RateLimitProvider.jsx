import { useEffect } from 'react'
import { useRateLimitToast } from './RateLimitToast'
import { setRateLimitToastCallback } from '../lib/apiBase'

/** Registers global 429 toast handling for all authenticated routes. */
export default function RateLimitProvider({ children }) {
  const { showToast, ToastComponent } = useRateLimitToast()

  useEffect(() => {
    setRateLimitToastCallback(showToast)
    return () => setRateLimitToastCallback(null)
  }, [showToast])

  return (
    <>
      {children}
      {ToastComponent}
    </>
  )
}
