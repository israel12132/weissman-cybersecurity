/* @weissman-forensic-page
 * Identity Matrix — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import IdentityMatrixTab from '../../components/cockpit/IdentityMatrixTab'

export default function IdentityMatrixPage() {
  return (
    <WidgetShell titleKey="nav.identity_matrix" badge="IDENTITY" badgeColor="#67e8f9">
      <IdentityMatrixTab />
    </WidgetShell>
  )
}
