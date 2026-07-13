/**
 * Protected-route provider stack — MUST wrap every authenticated route outlet.
 *
 * Order (outer → inner):
 *   ClientProvider      — tenant/client selection, integrations
 *   TelemetryProvider   — SSE /api/telemetry/stream (single connection)
 *   WarRoomProvider     — war-room state; consumes TelemetryProvider.subscribe
 *   EngineHubProvider   — shared scan params across PageShell / hubs
 *   EngineManifestProvider — engine C2 capability manifests
 *
 * Auth, Toast, RateLimit live in TacticalProviders (main.jsx) above the router.
 * EngineC2ControlProvider is scoped per MorphingEngineChrome / PageShell.
 */
import { ClientProvider } from '../context/ClientContext'
import { TelemetryProvider } from '../context/TelemetryContext'
import { NotificationProvider } from '../context/NotificationContext'
import { WarRoomProvider } from '../context/WarRoomContext'
import { EngineHubProvider } from '../context/EngineHubContext'
import { EngineManifestProvider } from '../engineC2/EngineManifestContext'
import IdleTimeoutWatcher from '../components/auth/IdleTimeoutWatcher'

export function ProtectedProviders({ children }) {
  return (
    <ClientProvider>
      <TelemetryProvider>
        <NotificationProvider>
          <WarRoomProvider>
            <EngineHubProvider>
              <EngineManifestProvider>
                <IdleTimeoutWatcher />
                {children}
              </EngineManifestProvider>
            </EngineHubProvider>
          </WarRoomProvider>
        </NotificationProvider>
      </TelemetryProvider>
    </ClientProvider>
  )
}
