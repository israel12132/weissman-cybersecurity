import React from 'react'
import { useTelemetry } from '../../context/TelemetryContext'

export default function ToastContainer() {
  const { toasts, removeToast } = useTelemetry()
  if (toasts.length === 0) return null
  return (
    <div
      className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 max-w-md pointer-events-auto"
      role="alert"
      aria-live="assertive"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          onClick={() => removeToast(t.id)}
          className={`
            rounded-lg border-2 px-4 py-3 shadow-lg font-mono text-sm
            transition-all duration-200 cursor-pointer
            ${t.severity === 'error'
              ? 'bg-[#1a0505] border-[#ff3333] text-[#ff6b6b] hover:border-[#ff5555] hover:shadow-[0_0_20px_rgba(255,51,51,0.25)]'
              : 'bg-[#051a0a] border-[#22d3ee] text-[#22d3ee]'
            }
          `}
        >
          {t.engine && (
            <span className="text-[10px] uppercase tracking-wider text-[#6b7280] block mb-1">
              {t.engine}
            </span>
          )}
          <span className="break-words">{t.message}</span>
        </div>
      ))}
    </div>
  )
}
