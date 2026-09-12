/**
 * Operator crown-jewel board — live PATCH /api/risk-graph/nodes/:id/flags.
 * Extracted from Attack Paths so sibling PRs can reuse it without importing the page.
 */
import EmptyState from '../ui/EmptyState'
import Button from '../ui/Button'

export const ATTACK_PATHS_NS = 'pages.attackPaths'

export function snapshotHasNoJewels(snapshot) {
  return Number(snapshot?.jewel_count) === 0
}

export function graphNodesFromPayload(payload) {
  if (Array.isArray(payload?.nodes)) return payload.nodes
  if (Array.isArray(payload)) return payload
  return []
}

/** Live operator flag. Never infers jewels — only flips the node the operator clicked. */
export async function patchCrownJewelFlag(apiFetch, node) {
  if (!node?.id) {
    const err = new Error('missing graph node id')
    err.code = 'missing_node'
    throw err
  }
  const data = await apiFetch(`/api/risk-graph/nodes/${encodeURIComponent(node.id)}/flags`, {
    method: 'PATCH',
    body: { crown_jewel: !node.crown_jewel },
  })
  if (data?.ok === false) throw new Error(data.detail || 'flag failed')
  return data
}

export default function CrownJewelBoard({ nodes, busyId, onToggle, t }) {
  const list = Array.isArray(nodes) ? nodes : []
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-4">
      <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
        {t(`${ATTACK_PATHS_NS}.jewel_board`)}
      </h2>
      <p className="text-[11px] text-[var(--text-muted)] mb-3">{t(`${ATTACK_PATHS_NS}.jewel_board_hint`)}</p>
      {list.length === 0 ? (
        <EmptyState icon="shield" title={t(`${ATTACK_PATHS_NS}.no_graph_title`)} body={t(`${ATTACK_PATHS_NS}.no_graph_body`)} />
      ) : (
        <ul className="space-y-2 max-h-72 overflow-y-auto">
          {list.map((n) => (
            <li
              key={n.id}
              className="flex items-center justify-between gap-3 rounded-lg border border-[var(--border-default)] px-3 py-2"
            >
              <div className="min-w-0">
                <div className="text-[12px] text-[var(--text-primary)] truncate">
                  {n.label || n.graph_key || `#${n.id}`}
                </div>
                <div className="text-[10px] font-mono text-[var(--text-muted)]">
                  {n.node_type || 'node'}
                  {n.internet_exposed ? ` · ${t(`${ATTACK_PATHS_NS}.entry_flag`)}` : ''}
                </div>
              </div>
              <Button
                variant="unstyled"
                type="button"
                data-testid={`crown-jewel-${n.id}`}
                disabled={busyId === n.id}
                onClick={() => onToggle(n)}
                className={`shrink-0 text-[10px] font-mono px-2.5 py-1 rounded-lg border ${
                  n.crown_jewel
                    ? 'border-violet-400/50 bg-violet-500/20 text-violet-100'
                    : 'border-[var(--border-default)] text-[var(--text-muted)] hover:border-violet-400/40'
                }`}
              >
                {n.crown_jewel ? t(`${ATTACK_PATHS_NS}.jewel_on`) : t(`${ATTACK_PATHS_NS}.jewel_off`)}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
