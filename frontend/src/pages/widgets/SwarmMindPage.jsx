/* @weissman-forensic-page
 * Swarm-Mind — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import SwarmMindTab from '../../components/cockpit/SwarmMindTab'

export default function SwarmMindPage() {
  return (
    <WidgetShell titleKey="nav.swarm_mind" badge="SWARM" badgeColor="#818cf8">
      <SwarmMindTab />
    </WidgetShell>
  )
}
