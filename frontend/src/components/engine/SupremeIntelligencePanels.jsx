import React, { useMemo } from 'react'

const SUPREME_CATEGORIES = new Set([
  'toxic_combination',
  'remediation_roadmap',
  'agent_guidance',
  'attack_path',
  'posture_summary',
  'posture',
  'graphql_metrics',
  'cicd_metrics',
  'serverless_metrics',
  'dry_run',
  'summary',
])

export function extractSupremeFromFindings(findings = []) {
  const list = Array.isArray(findings) ? findings : []
  const toxic = list.find((f) => f.category === 'toxic_combination') || null
  const roadmap = list.find((f) => f.category === 'remediation_roadmap') || null
  const agentGaps = list.filter((f) => f.category === 'agent_guidance')
  const paths = list.filter((f) => f.category === 'attack_path')
  const posture = list.find((f) =>
    f.category === 'posture_summary' || f.category === 'posture' || f.summary === true,
  ) || null
  const categoryScores =
    posture?.evidence?.category_scores
    || roadmap?.evidence?.category_scores
    || toxic?.evidence?.category_scores
    || null
  const regular = list.filter((f) => !SUPREME_CATEGORIES.has(f.category))
  return { toxic, roadmap, agentGaps, paths, posture, categoryScores, regular }
}

function scoreColor(v) {
  if (v >= 80) return '#4ade80'
  if (v >= 50) return '#fbbf24'
  return '#f87171'
}

export function CategoryScoresPanel({ scores, title = 'Security domain scores', axes }) {
  if (!scores || typeof scores !== 'object') return null
  const entries = axes?.length
    ? axes.map(([k, label]) => [k, label])
    : Object.entries(scores).map(([k]) => [k, k.replace(/_/g, ' ')])
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-4">
      <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-3">{title}</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {entries.map(([k, label]) => {
          const v = Number(scores[k] ?? 0)
          return (
            <div key={k}>
              <div className="flex justify-between text-[10px] font-mono text-[var(--text-muted)] mb-1">
                <span className="truncate pr-1">{label}</span>
                <span style={{ color: scoreColor(v) }}>{v}</span>
              </div>
              <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${v}%`, backgroundColor: scoreColor(v) }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function ToxicBanner({ finding, title = 'Toxic combination detected' }) {
  if (!finding) return null
  return (
    <div className="rounded-2xl border-2 border-rose-500/50 bg-gradient-to-r from-rose-950/50 via-red-950/30 to-black/40 p-4 mb-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300 mb-1">{title}</p>
      <h3 className="text-sm font-bold text-rose-100 leading-snug">{finding.title}</h3>
      {finding.description && (
        <p className="text-xs text-[var(--text-tertiary)] mt-2 leading-relaxed">{finding.description}</p>
      )}
    </div>
  )
}

export function RoadmapCard({ finding, title = 'Prioritized remediation roadmap' }) {
  const steps = finding?.evidence?.roadmap
  if (!Array.isArray(steps) || steps.length === 0) return null
  return (
    <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/15 p-4 mb-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/70 mb-3">{title}</p>
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-xs font-mono">
            <span className="shrink-0 text-emerald-400 font-bold">{s.priority ?? i + 1}.</span>
            <span className="text-[var(--text-secondary)]">
              <b className="text-emerald-200">{s.action}</b>
              {s.detail ? ` — ${s.detail}` : ''}
              {s.tier && <span className="text-[var(--text-muted)]"> ({s.tier})</span>}
            </span>
          </li>
        ))}
      </ol>
    </div>
  )
}

export function AgentGapPanel({ findings, title = 'Agent-required capabilities' }) {
  const gaps = Array.isArray(findings) ? findings : []
  if (!gaps.length) return null
  return (
    <div className="rounded-xl border border-violet-500/25 bg-violet-950/15 p-4 mb-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-violet-300/70 mb-3">{title}</p>
      <ul className="space-y-2">
        {gaps.map((f, i) => (
          <li key={i} className="text-xs font-mono text-[var(--text-secondary)] leading-relaxed">
            <span className="text-violet-300">○</span> {f.title}
            {f.description && <span className="block text-[var(--text-muted)] mt-0.5 pl-4">{f.description}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

export function AttackPathsPanel({ paths, title = 'Attack paths' }) {
  const list = Array.isArray(paths) ? paths : []
  if (!list.length) return null
  return (
    <div className="rounded-xl border border-amber-500/25 bg-amber-950/10 p-4 mb-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-amber-300/70 mb-3">
        {title} ({list.length})
      </p>
      <div className="space-y-2 max-h-48 overflow-auto">
        {list.map((p, i) => (
          <div key={i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2">
            <p className="text-xs font-mono text-[var(--text-primary)]">{p.title}</p>
            {Array.isArray(p.attack_path) && (
              <ol className="mt-1 list-decimal list-inside text-[10px] font-mono text-[var(--text-muted)]">
                {p.attack_path.map((s, j) => <li key={j}>{s}</li>)}
              </ol>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default function SupremeIntelligencePanels({
  findings,
  labels = {},
  categoryAxes,
}) {
  const supreme = useMemo(() => extractSupremeFromFindings(findings), [findings])
  const L = {
    categoryScores: labels.categoryScores || 'Security domain scores',
    toxicTitle: labels.toxicTitle || 'Toxic combination detected',
    roadmapTitle: labels.roadmapTitle || 'Prioritized remediation roadmap',
    agentTitle: labels.agentTitle || 'Agent-required capabilities',
    pathsTitle: labels.pathsTitle || 'Attack paths',
  }

  if (!supreme.toxic && !supreme.roadmap && !supreme.categoryScores && !supreme.agentGaps.length && !supreme.paths.length) {
    return null
  }

  return (
    <>
      <ToxicBanner finding={supreme.toxic} title={L.toxicTitle} />
      {supreme.categoryScores && (
        <CategoryScoresPanel scores={supreme.categoryScores} title={L.categoryScores} axes={categoryAxes} />
      )}
      <RoadmapCard finding={supreme.roadmap} title={L.roadmapTitle} />
      <AttackPathsPanel paths={supreme.paths} title={L.pathsTitle} />
      <AgentGapPanel findings={supreme.agentGaps} title={L.agentTitle} />
    </>
  )
}
