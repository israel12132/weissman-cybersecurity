/* @weissman-forensic-page
 * Immersive live War Room theater — a first-class, deep-linkable route
 * (/war-room) rendering the Command Center surface with the war room in front:
 * converging global attack vectors, DEFCON threat level, tracked campaigns and
 * threat actors, kill-chain stage, and a HITL response console. Evidence-only
 * theater surface, like /sovereign and /operations.
 */
import CommandCenter from './CommandCenter'

export default function WarRoom() {
  return <CommandCenter initialView="warroom" />
}
