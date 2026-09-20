/* @weissman-forensic-page
 * Global Edge Swarm — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import GlobalEdgeSwarmMap from '../../components/cockpit/GlobalEdgeSwarmMap'

export default function EdgeSwarmPage() {
  return (
    <WidgetShell titleKey="nav.edge_swarm" badge="EDGE" badgeColor="#22d3ee">
      <GlobalEdgeSwarmMap />
    </WidgetShell>
  )
}
