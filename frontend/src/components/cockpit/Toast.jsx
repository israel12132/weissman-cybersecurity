/**
 * Telemetry toast bridge — renders engine/scan notifications through the shared
 * premium toast stack. Replaces the legacy duplicate styling in this module.
 *
 * @deprecated Import ToastViewport from '../ui/Toaster' for new code; this wrapper
 * remains for TelemetryContext consumers inside Cockpit.
 */
import React, { useMemo } from 'react'
import { useTelemetry } from '../../context/TelemetryContext'
import { ToastViewport, severityToVariant } from '../ui/Toaster'

export default function ToastContainer() {
  const { toasts, removeToast } = useTelemetry()

  const items = useMemo(
    () => toasts.map((t) => ({
      id: t.id,
      variant: severityToVariant(t.severity),
      message: t.message,
      subtitle: t.engine || undefined,
      ttl: 8000,
    })),
    [toasts],
  )

  return (
    <ToastViewport
      items={items}
      dismiss={removeToast}
      className="top-[4.5rem]"
    />
  )
}
