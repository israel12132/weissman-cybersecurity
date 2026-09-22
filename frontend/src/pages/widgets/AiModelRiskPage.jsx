/* @weissman-forensic-page
 * AI-Model-Risk — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import AIModelRiskTab from '../../components/cockpit/AIModelRiskTab'

export default function AiModelRiskPage() {
  return (
    <WidgetShell titleKey="nav.ai_model_risk" badge="MODEL" badgeColor="#fbbf24">
      <AIModelRiskTab />
    </WidgetShell>
  )
}
