import React, { useState, useEffect, useId } from 'react'
import { motion } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import {
  AlertTriangle,
  ShieldAlert,
  Zap,
  Activity,
  Globe,
  Smartphone,
  Cloud,
} from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const GLASS_CARD =
  'rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 transition-all duration-300 hover:border-white/20 hover:shadow-[0_0_30px_rgba(0,0,0,0.3)]'

function MiniSparkline({ data, color = '#22d3ee', id: idProp }) {
  const id = useId()
  const gradientId = idProp || `spark-${id.replace(/:/g, '')}-${color.replace('#', '')}`
  return (
    <div className="h-8 w-full mt-2">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.4} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <Area
            type="monotone"
            dataKey="v"
            stroke={color}
            strokeWidth={1.2}
            fill={`url(#${gradientId})`}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

function RiskGauge({ score }) {
  const normalized = Math.max(0, Math.min(100, Number(score) || 0))
  const grade = normalized >= 90 ? 'A' : normalized >= 80 ? 'B' : normalized >= 70 ? 'C' : normalized >= 50 ? 'D' : 'F'
  const gradeColor =
    grade === 'A'
      ? '#22d3ee'
      : grade === 'B'
        ? '#4ade80'
        : grade === 'C'
          ? '#fbbf24'
          : grade === 'D'
            ? '#f97316'
            : '#ef4444'

  return (
    <div className="relative flex items-center justify-center">
      <svg viewBox="0 0 200 200" className="w-full max-w-[280px] aspect-square">
        <defs>
          <linearGradient id="gaugeBg" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#1f2937" />
            <stop offset="100%" stopColor="#111827" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Outer ring */}
        <circle
          cx="100"
          cy="100"
          r="88"
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="12"
        />
        {/* Progress arc */}
        <circle
          cx="100"
          cy="100"
          r="88"
          fill="none"
          stroke={gradeColor}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${(normalized / 100) * 415} 415`}
          transform="rotate(-90 100 100)"
          opacity={0.9}
          style={{ filter: `drop-shadow(0 0 12px ${gradeColor})` }}
        />
        {/* Inner glow ring */}
        <circle cx="100" cy="100" r="70" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="1" />
        {/* Center grade */}
        <text
          x="100"
          y="108"
          textAnchor="middle"
          className="text-5xl font-bold tabular-nums"
          fill={gradeColor}
          style={{
            fontFamily: 'system-ui, sans-serif',
            filter: `drop-shadow(0 0 20px ${gradeColor})`,
          }}
        >
          {grade}
        </text>
      </svg>
    </div>
  )
}

export default function OverviewTab() {
  const { selectedClient, selectedClientId } = useClient()
  const { suggestedWidget, setSuggestedWidget } = useWarRoom()
  const [stats, setStats] = useState({
    total_vulnerabilities: 0,
    security_score: 0,
    active_scans: 0,
  })
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setLoading(true)
      try {
        const [statsRes, findingsRes] = await Promise.all([
          apiFetch('/api/dashboard/stats'),
          selectedClientId ? apiFetch(`/api/clients/${selectedClientId}/findings`) : null,
        ])
        if (cancelled) return
        if (statsRes.ok) {
          const d = await statsRes.json()
          setStats({
            total_vulnerabilities: d.total_vulnerabilities ?? 0,
            security_score: d.security_score ?? 0,
            active_scans: d.active_scans ? 1 : 0,
            attack_surface_targets: d.attack_surface_targets ?? 0,
            attack_surface_paths: d.attack_surface_paths ?? 0,
          })
        }
        if (findingsRes?.ok) {
          const d = await findingsRes.json()
          setFindings(d.findings ?? [])
        } else {
          setFindings([])
        }
      } catch (_) {
        if (!cancelled) setFindings([])
      }
      if (!cancelled) setLoading(false)
    }
    load()
    return () => { cancelled = true }
  }, [selectedClientId])

  const critical = findings.filter((f) => (f.severity || '').toLowerCase().includes('critical')).length
  const high = findings.filter((f) => (f.severity || '').toLowerCase().includes('high')).length
  React.useEffect(() => {
    if (critical > 0 && setSuggestedWidget) {
      setSuggestedWidget({
        type: 'severity_breakdown',
        message: 'High-critical finding detected. AI suggests: View severity breakdown and prioritize remediation.',
      })
    }
  }, [critical, setSuggestedWidget])
  const medium = findings.filter((f) =>
    (f.severity || '').toLowerCase().includes('medium') || (f.severity || '').toLowerCase().includes('med'),
  ).length
  const zeroDayCount = findings.filter((f) => (f.source || '').includes('zero_day')).length
  const score = selectedClientId ? (stats.security_score ?? 0) : 0

  const severityBarData = [
    { name: 'Critical', count: critical, color: '#ef4444' },
    { name: 'High', count: high, color: '#a855f7' },
    { name: 'Medium', count: medium, color: '#22d3ee' },
  ].filter((d) => d.count > 0)

  const sparkData = [
    { v: 12 },
    { v: 8 },
    { v: 14 },
    { v: 6 },
    { v: 18 },
    { v: 10 },
    { v: stats.total_vulnerabilities || 5 },
  ]

  const attackSurfaceTargets = stats.attack_surface_targets ?? 0
  const attackSurfacePaths = stats.attack_surface_paths ?? 0
  const attackSurfaceTotal = Math.max(1, attackSurfaceTargets + attackSurfacePaths)
  const attackSurfaceData = [
    { label: 'Targets (OSINT+ASM)', value: attackSurfaceTargets, color: '#22d3ee' },
    { label: 'Paths (wordlist)', value: attackSurfacePaths, color: '#a855f7' },
  ].filter((d) => d.value > 0)
  const attackSurfaceDataWithDefaults = attackSurfaceData.length
    ? attackSurfaceData
    : [
        { label: 'Targets', value: 0, color: '#22d3ee' },
        { label: 'Paths', value: 0, color: '#a855f7' },
      ]

  if (!selectedClientId) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className={`${GLASS_CARD} max-w-md text-center py-12`}>
          <p className="text-white/80 text-sm uppercase tracking-widest mb-2">No client selected</p>
          <p className="text-white/50 text-xs">Select a client from the sidebar to view the overview.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-8">
      {/* Section header */}
      <div>
        <h2 className="text-xs font-semibold text-white/60 uppercase tracking-[0.2em] mb-1">
          Security Overview
        </h2>
        <p className="text-white/40 text-sm">
          {selectedClient?.name || `Client ${selectedClientId}`} — real-time metrics
        </p>
      </div>

      {/* AI Suggested visualization (Ollama / Architect) */}
      {suggestedWidget?.message && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-[#22d3ee]/10 border border-[#22d3ee]/30 p-4 flex items-center gap-4"
        >
          <span className="text-2xl">⚡</span>
          <div>
            <p className="text-xs font-semibold text-[#22d3ee] uppercase tracking-wider">AI Suggestion</p>
            <p className="text-sm text-white/90 mt-0.5">{suggestedWidget.message}</p>
          </div>
        </motion.div>
      )}

      {/* Top row: 4 metric cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              Active Incidents
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400/80" />
          </div>
          <p className="text-2xl font-bold text-white mt-1 tabular-nums">
            {loading ? '—' : findings.length}
          </p>
          <MiniSparkline data={sparkData.map((_, i) => ({ v: sparkData[i]?.v ?? 0 }))} color="#fbbf24" />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              Threat Exposure
            </span>
            <ShieldAlert className="w-4 h-4 text-[#22d3ee]/80" />
          </div>
          <p className="text-2xl font-bold text-[#22d3ee] mt-1 tabular-nums">
            {loading ? '—' : stats.total_vulnerabilities}
          </p>
          <MiniSparkline data={sparkData} color="#22d3ee" />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              Zero-Day Risk
            </span>
            <Zap className="w-4 h-4 text-[#a855f7]/80" />
          </div>
          <p className="text-2xl font-bold text-[#a855f7] mt-1 tabular-nums">
            {loading ? '—' : zeroDayCount}
          </p>
          <MiniSparkline
            data={[ { v: 0 }, { v: zeroDayCount }, { v: zeroDayCount } ]}
            color="#a855f7"
          />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              System Health
            </span>
            <Activity className="w-4 h-4 text-emerald-400/80" />
          </div>
          <p className="text-2xl font-bold mt-1 tabular-nums" style={{
            color: score >= 70 ? '#4ade80' : score >= 40 ? '#fbbf24' : '#ef4444',
          }}>
            {loading ? '—' : `${score}%`}
          </p>
          <MiniSparkline
            data={[ { v: 30 }, { v: 50 }, { v: 45 }, { v: score }, { v: score } ]}
            color={score >= 70 ? '#4ade80' : score >= 40 ? '#fbbf24' : '#ef4444'}
          />
        </div>
      </div>

      {/* Center: Gauge + Bar chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className={`${GLASS_CARD} flex flex-col items-center justify-center min-h-[320px]`}>
          <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-4">
            Security Risk Grade
          </h3>
          <RiskGauge score={score} />
        </div>
        <div className={`${GLASS_CARD} min-h-[320px]`}>
          <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-4">
            Vulnerabilities by Severity
          </h3>
          {severityBarData.length > 0 ? (
            <div className="h-64 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityBarData} layout="vertical" margin={{ left: 0, right: 20 }}>
                  <XAxis type="number" stroke="rgba(255,255,255,0.3)" fontSize={11} />
                  <YAxis type="category" dataKey="name" stroke="rgba(255,255,255,0.3)" fontSize={11} width={70} />
                  <Tooltip
                    contentStyle={{
                      background: 'rgba(0,0,0,0.8)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '12px',
                    }}
                    labelStyle={{ color: 'rgba(255,255,255,0.8)' }}
                  />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                    {severityBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-white/30 text-sm">
              No severity data yet
            </div>
          )}
        </div>
      </div>

      {/* Bottom: Attack Surface Growth (OSINT → ASM → path wordlist) */}
      <div className={GLASS_CARD}>
        <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-6">
          Attack Surface Growth
        </h3>
        <div className="space-y-5">
          {attackSurfaceDataWithDefaults.map(({ label, value, color }) => (
            <div key={label}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-white/80 flex items-center gap-2">
                  {label === 'Web' && <Globe className="w-4 h-4 text-[#22d3ee]/80" />}
                  {label === 'Mobile' && <Smartphone className="w-4 h-4 text-[#a855f7]/80" />}
                  {label === 'Cloud' && <Cloud className="w-4 h-4 text-[#4ade80]/80" />}
                  {label}
                </span>
                <span className="text-xs font-mono text-white/50 tabular-nums">{value}%</span>
              </div>
              <div className="h-3 rounded-full bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${value}%`,
                    background: `linear-gradient(90deg, ${color}, ${color}99)`,
                    boxShadow: `0 0 20px ${color}40`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
