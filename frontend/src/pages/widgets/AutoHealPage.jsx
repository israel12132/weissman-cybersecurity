/* @weissman-forensic-page
 * Auto-Heal — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import AutoHealTab from '../../components/cockpit/AutoHealTab'

export default function AutoHealPage() {
  return (
    <WidgetShell titleKey="nav.auto_heal" badge="HEAL" badgeColor="#34d399">
      <AutoHealTab />
    </WidgetShell>
  )
}
