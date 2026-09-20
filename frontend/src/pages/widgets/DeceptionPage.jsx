/* @weissman-forensic-page
 * Deception Grid — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import DeceptionGridTab from '../../components/cockpit/DeceptionGridTab'

export default function DeceptionPage() {
  return (
    <WidgetShell titleKey="nav.deception" badge="DECOY" badgeColor="#a78bfa">
      <DeceptionGridTab />
    </WidgetShell>
  )
}
