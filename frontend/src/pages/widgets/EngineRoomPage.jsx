/* @weissman-forensic-page
 * Engine Room — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import EngineRoomTab from '../../components/cockpit/EngineRoomTab'

export default function EngineRoomPage() {
  return (
    <WidgetShell titleKey="nav.engine_room" badge="MESH" badgeColor="#22d3ee">
      <EngineRoomTab />
    </WidgetShell>
  )
}
