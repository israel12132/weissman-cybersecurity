/* @weissman-forensic-page
 * Neural Engine Web — promoted from the cockpit to a first-class menu route. Live evidence
 * surface rendered inside the forensic PageShell. */
import WidgetShell from '../../components/widget/WidgetShell'
import NeuralEngineWeb from '../../components/warroom/NeuralEngineWeb'

export default function NeuralWebPage() {
  return (
    <WidgetShell titleKey="nav.neural_web" badge="GRAPH" badgeColor="#8b5cf6">
      <div className="flex justify-center py-4"><NeuralEngineWeb width={920} height={480} /></div>
    </WidgetShell>
  )
}
