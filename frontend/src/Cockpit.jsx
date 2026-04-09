import React from 'react'
import { ClientProvider } from './context/ClientContext'
import { TelemetryProvider } from './context/TelemetryContext'
import { WarRoomProvider } from './context/WarRoomContext'
import GlobalNexus from './components/cockpit/GlobalNexus'
import ClientCockpit from './components/cockpit/ClientCockpit'
import TargetScopePanel from './components/cockpit/TargetScopePanel'
import ToastContainer from './components/cockpit/Toast'

export default function Cockpit({ ceoIntegrated = false }) {
  return (
    <ClientProvider>
      <TelemetryProvider>
        <WarRoomProvider>
        <div
          className="flex flex-col lg:flex-row h-[100dvh] max-h-[100dvh] w-full max-w-[100vw] min-h-0 overflow-hidden min-h-[100dvh]"
          style={{
            background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #111827 0%, #09090b 50%, #030712 100%)',
          }}
        >
          <GlobalNexus ceoIntegrated={ceoIntegrated} />
          <ClientCockpit ceoIntegrated={ceoIntegrated} />
          <TargetScopePanel ceoIntegrated={ceoIntegrated} />
        </div>
        <ToastContainer />
        </WarRoomProvider>
      </TelemetryProvider>
    </ClientProvider>
  )
}
