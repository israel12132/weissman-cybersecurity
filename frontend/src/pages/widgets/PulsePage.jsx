/* @weissman-forensic-page
 * System Pulse — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import SystemPulseEKG from '../../components/warroom/SystemPulseEKG'

export default function PulsePage() {
  return (
    <WidgetShell titleKey="nav.pulse" badge="PULSE" badgeColor="#34d399">
      <div className="py-4"><SystemPulseEKG /></div>
    </WidgetShell>
  )
}
