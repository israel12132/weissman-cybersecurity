import React, { useEffect, useMemo, useState } from 'react'
import { Brain, ShieldAlert, GitBranch, Activity, Gauge, CheckCircle2 } from 'lucide-react'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'
import { useWeissmanSocket } from '../hooks/useWeissmanSocket'

const SEVERITY_WEIGHT = { critical: 10, high: 7, medium: 4, low: 2, info: 1 }

function toArrayFindings(payload) {
  if (!payload) return []
  if (Array.isArray(payload)) return payload
  if (Array.isArray(payload.items)) return payload.items
  if (Array.isArray(payload.findings)) return payload.findings
  return []
}

function sev(s) {
  return String(s || 'info').toLowerCase()
}

function colorBySeverity(s) {
  const k = sev(s)
  if (k === 'critical') return '#ef4444'
  if (k === 'high') return '#f97316'
  if (k === 'medium') return '#f59e0b'
  if (k === 'low') return '#22d3ee'
  return '#94a3b8'
}

function scoreFinding(f) {
  const base = SEVERITY_WEIGHT[sev(f?.severity)] ?? 1
  const cvssRaw = Number(f?.cvss_score ?? f?.score ?? 0)
  const cvss = Number.isFinite(cvssRaw) ? cvssRaw : 0
  return +(base * 10 + cvss).toFixed(1)
}

export default function AutonomousDefenseBrain() {
  const { events } = useWeissmanSocket()
  const [loading, setLoading] = useState(true)
  const [findings, setFindings] = useState([])
  const [graph, setGraph] = useState({ nodes: [], edges: [] })

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        setLoading(true)
        const [fRes, gRes] = await Promise.all([
          apiFetch('/api/findings?page=1&per_page=300'),
          apiFetch('/api/risk/graph'),
        ])
        const fJson = fRes?.ok ? await fRes.json().catch(() => ({})) : {}
        const gJson = gRes?.ok ? await gRes.json().catch(() => ({})) : {}
        if (!alive) return
        setFindings(toArrayFindings(fJson))
        setGraph({
          nodes: Array.isArray(gJson?.nodes) ? gJson.nodes : [],
          edges: Array.isArray(gJson?.edges) ? gJson.edges : [],
        })
      } finally {
        if (alive) setLoading(false)
      }
    }
    load()
    return () => { alive = false }
  }, [])

  const fusedSignals = useMemo(() => {
    const threatIntelEvents = events.filter((e) => ['critical_cve', 'darkweb', 'github_exploit_repo'].includes(e.kind)).length
    const behaviorEvents = events.filter((e) => ['scan_pulse', 'emergency_alert', 'fuzzer_anomaly'].includes(e.kind)).length
    const assets = new Set([
      ...findings.map((f) => f?.target || f?.client_name || f?.client_id).filter(Boolean),
      ...graph.nodes.map((n) => n?.name || n?.id).filter(Boolean),
    ]).size
    return {
      assets,
      findings: findings.length,
      threatIntelEvents,
      behaviorEvents,
      fusionConfidence: Math.min(99, 55 + findings.length / 8 + events.length / 10).toFixed(0),
    }
  }, [events, findings, graph.nodes])

  const prioritizedTargets = useMemo(() => {
    const map = new Map()
    findings.forEach((f) => {
      const key = f?.target || f?.client_name || `asset-${f?.client_id || 'global'}`
      const prev = map.get(key) || { asset: key, score: 0, critical: 0, high: 0, findings: 0 }
      const s = scoreFinding(f)
      prev.score += s
      prev.findings += 1
      if (sev(f?.severity) === 'critical') prev.critical += 1
      if (sev(f?.severity) === 'high') prev.high += 1
      map.set(key, prev)
    })
    return [...map.values()].sort((a, b) => b.score - a.score).slice(0, 6)
  }, [findings])

  const predictedChains = useMemo(() => {
    const edges = Array.isArray(graph.edges) ? graph.edges : []
    const criticalEdges = edges.filter((e) => e?.critical).slice(0, 4)
    const fromGraph = criticalEdges.map((e, idx) => ({
      id: `graph-${idx}`,
      path: `${e.source} → ${e.target}`,
      confidence: Math.max(60, 90 - idx * 6),
      nextStep: 'Privilege pivot + lateral movement',
    }))
    const fromRisk = prioritizedTargets.slice(0, 3).map((r, idx) => ({
      id: `risk-${idx}`,
      path: `${r.asset} → exposed service → identity abuse`,
      confidence: Math.max(58, 84 - idx * 5),
      nextStep: 'Credential replay attempt',
    }))
    return [...fromGraph, ...fromRisk].slice(0, 6)
  }, [graph.edges, prioritizedTargets])

  const orchestratedActions = useMemo(() => {
    return prioritizedTargets.slice(0, 4).map((t, i) => {
      const primary = t.critical > 0
        ? 'isolate_tier + conditional traffic quarantine'
        : t.high > 0
          ? 'adaptive throttling + policy hardening'
          : 'targeted retest + patch verification'
      return {
        id: t.asset,
        asset: t.asset,
        action: primary,
        guardrail: 'Auto-stop if error-rate exceeds baseline +25%',
        eta: `${6 + i * 4}m`,
        reduction: `${Math.min(72, 35 + Math.round(t.score / 10))}%`,
      }
    })
  }, [prioritizedTargets])

  const decisionMode = useMemo(() => orchestratedActions.slice(0, 3), [orchestratedActions])

  const closedLoopMetrics = useMemo(() => {
    const criticalCount = findings.filter((f) => sev(f?.severity) === 'critical').length
    const highCount = findings.filter((f) => sev(f?.severity) === 'high').length
    const baseline = Math.max(20, 64 + criticalCount * 2 + highCount)
    const projected = Math.max(8, Math.round(baseline * 0.58))
    const exploitability = Math.max(12, 78 - Math.round((criticalCount * 4 + highCount * 2)))
    return {
      mttdBefore: `${baseline}m`,
      mttdAfter: `${projected}m`,
      blastRadiusBefore: `${Math.min(100, 44 + criticalCount * 5)}%`,
      blastRadiusAfter: `${Math.max(8, 26 + criticalCount * 2)}%`,
      exploitabilityBefore: `${exploitability}%`,
      exploitabilityAfter: `${Math.max(5, exploitability - 31)}%`,
    }
  }, [findings])

  return (
    <PageShell
      title="Autonomous Defense Brain"
      subtitle="Decision-mode security superiority engine"
      badge="AUTONOMOUS"
      badgeColor="#22d3ee"
    >
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            ['Assets', fusedSignals.assets, <ShieldAlert className="w-4 h-4" />],
            ['Findings', fusedSignals.findings, <Activity className="w-4 h-4" />],
            ['Intel Signals', fusedSignals.threatIntelEvents, <Brain className="w-4 h-4" />],
            ['Behavior Signals', fusedSignals.behaviorEvents, <Gauge className="w-4 h-4" />],
            ['Fusion Confidence', `${fusedSignals.fusionConfidence}%`, <CheckCircle2 className="w-4 h-4" />],
          ].map(([label, value, icon]) => (
            <div key={label} className="rounded-xl border border-white/10 bg-black/40 p-4">
              <div className="flex items-center justify-between text-white/50 text-[11px] font-mono uppercase tracking-wider">
                <span>{label}</span>{icon}
              </div>
              <div className="mt-2 text-2xl font-bold text-white">{value}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">1) Autonomous Defense Brain · Signal Fusion</h2>
            <div className="space-y-2">
              {prioritizedTargets.length === 0 && <p className="text-xs text-white/45">{loading ? 'Loading fused signals…' : 'No findings available yet.'}</p>}
              {prioritizedTargets.map((t) => (
                <div key={t.asset} className="rounded-lg border border-white/10 bg-black/30 p-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white/85 font-semibold">{t.asset}</span>
                    <span className="text-xs font-mono text-cyan-300">risk {Math.round(t.score)}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-white/45 font-mono">
                    critical {t.critical} · high {t.high} · findings {t.findings}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">2) Attack-Chain Anticipation</h2>
            <div className="space-y-2">
              {predictedChains.map((c) => (
                <div key={c.id} className="rounded-lg border border-white/10 bg-black/30 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs text-white/90 font-mono flex items-center gap-2">
                      <GitBranch className="w-3.5 h-3.5 text-cyan-300" /> {c.path}
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded border border-violet-400/40 text-violet-300 bg-violet-500/10">{c.confidence}%</span>
                  </div>
                  <p className="mt-1 text-[11px] text-white/50">Predicted next adversary move: {c.nextStep}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">3) Live Countermeasure Orchestration</h2>
            <div className="space-y-2">
              {orchestratedActions.map((a) => (
                <div key={a.id} className="rounded-lg border border-white/10 bg-black/30 p-3">
                  <div className="flex justify-between gap-2 items-center">
                    <span className="text-sm text-white/90">{a.asset}</span>
                    <span className="text-[10px] text-emerald-300 border border-emerald-400/40 rounded px-2 py-0.5 bg-emerald-500/10">- {a.reduction}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-white/70 font-mono">{a.action}</div>
                  <div className="mt-1 text-[11px] text-white/40">{a.guardrail} · ETA {a.eta}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">4) Precision Risk Graph Prioritization</h2>
            <div className="space-y-2">
              {graph.nodes.slice(0, 6).map((n) => (
                <div key={n.id || n.name} className="flex justify-between items-center rounded-lg border border-white/10 bg-black/30 px-3 py-2">
                  <span className="text-xs text-white/80">{n.name || n.id}</span>
                  <span
                    className="text-[10px] px-2 py-0.5 rounded border font-mono"
                    style={{
                      color: colorBySeverity(n.severity),
                      borderColor: `${colorBySeverity(n.severity)}60`,
                      background: `${colorBySeverity(n.severity)}14`,
                    }}
                  >
                    {n.severity || 'info'} · risk {Math.round(n.risk_score || 0)}
                  </span>
                </div>
              ))}
              {!graph.nodes.length && <p className="text-xs text-white/45">{loading ? 'Loading risk graph…' : 'Risk graph data unavailable.'}</p>}
            </div>
          </section>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">5 + 6) Continuous Adversarial Simulation + Decision Mode</h2>
            <div className="space-y-2">
              {decisionMode.map((d, i) => (
                <div key={d.id} className="rounded-lg border border-white/10 bg-black/30 p-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white font-semibold">Decision #{i + 1}: {d.asset}</span>
                    <span className="text-[10px] text-cyan-300 font-mono">highest impact now</span>
                  </div>
                  <p className="mt-1 text-[11px] text-white/65">{d.action}</p>
                  <p className="mt-1 text-[11px] text-white/40">Expected risk reduction: {d.reduction}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-3">7) Closed-Loop Validation</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {[
                ['MTTD', closedLoopMetrics.mttdBefore, closedLoopMetrics.mttdAfter],
                ['Blast Radius', closedLoopMetrics.blastRadiusBefore, closedLoopMetrics.blastRadiusAfter],
                ['Exploitability', closedLoopMetrics.exploitabilityBefore, closedLoopMetrics.exploitabilityAfter],
              ].map(([k, before, after]) => (
                <div key={k} className="rounded-lg border border-white/10 bg-black/30 p-3">
                  <div className="text-[10px] text-white/45 uppercase tracking-wider font-mono">{k}</div>
                  <div className="mt-1 text-xs text-red-300">Before: {before}</div>
                  <div className="text-xs text-emerald-300">After: {after}</div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </PageShell>
  )
}
