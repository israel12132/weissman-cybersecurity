/**
 * Shared page shell — delegates to MorphingEngineChrome (capability-based C2).
 */
import MorphingEngineChrome from '../engineC2/MorphingEngineChrome'

export default function PageShell(props) {
  return <MorphingEngineChrome {...props} />
}
