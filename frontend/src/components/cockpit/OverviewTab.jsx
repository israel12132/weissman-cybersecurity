import React, { useState, useEffect, useId } from 'react'
import { useTranslation } from 'react-i18next'
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
  Cloud,
} from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'
import LiveActivityFeed from './LiveActivityFeed'
import MitreCoverageHeatmap from './MitreCoverageHeatmap'
import TopMoversPanel from './TopMoversPanel'
import SeverityTrendChart from './SeverityTrendChart'

const GLASS_CARD =
  'rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 transition-all duration-300 hover:border-white/20 hover:shadow-[0_0_30px_rgba(0,0,0,0.3)]'

function SparklineOrEmpty({ data, color, emptyLabel }) {
  if (!Array.isArray(data) || data.length < 2) {
    return (
      <p className="text-[10px] text-white/30 font-mono mt-2 uppercase tracking-wider">
        {emptyLabel}
      </p>
    )
  }
  return <MiniSparkline data={data} color={color} />
}

function MiniSparkline({ data, color = '#22d3ee', id: idProp }) {
  const id = useId()
  const gradientId = idProp || `spark-${id.replace(/:/g, '')}-${color.replace('#', '')}`
  return (
    <div className="h-8 w-full mt-2">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart accessibilityLayer data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
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
        <circle
          cx="100"
          cy="100"
          r="88"
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="12"
        />
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
        <circle cx="100" cy="100" r="70" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="1" />
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
  const { t } = useTranslation()
  const { selectedClient, selectedClientId } = useClient()
  const { suggestedWidget, setSuggestedWidget } = useWarRoom()
  const [stats, setStats] = useState({
    total_vulnerabilities: 0,
    security_score: 0,
    active_scans: 0,
  })
  const [findings, setFindings] = useState([])
  const [incidentCount, setIncidentCount] = useState(0)
  const [trendSpark, setTrendSpark] = useState([])
  const [resolvedSpark, setResolvedSpark] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = async (isBackground = false) => {
      if (!isBackground) setLoading(true)
      try {
        const [statsRes, findingsRes, kpisRes, incidentsRes] = await Promise.all([
          apiFetch('/api/dashboard/stats'),
          selectedClientId ? apiFetch(`/api/clients/${selectedClientId}/findings`) : null,
          apiFetch('/api/dashboard/exec-kpis'),
          apiFetch('/api/soc/incidents'),
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
        if (kpisRes.ok) {
          const k = await kpisRes.json()
          const discovered = k?.trend?.discovered
          const resolved = k?.trend?.resolved
          if (Array.isArray(discovered) && discovered.length > 1) {
            setTrendSpark(discovered.map((v) => ({ v: Number(v) || 0 })))
          } else {
            setTrendSpark([])
          }
          if (Array.isArray(resolved) && resolved.length > 1) {
            setResolvedSpark(resolved.map((v) => ({ v: Number(v) || 0 })))
          } else {
            setResolvedSpark([])
          }
        }
        if (incidentsRes.ok) {
          const inc = await incidentsRes.json()
          const list = Array.isArray(inc?.incidents) ? inc.incidents : []
          setIncidentCount(list.filter((i) => (i.status || '').toLowerCase() !== 'closed').length)
        } else {
          setIncidentCount(0)
        }
      } catch (_) {
        if (!cancelled) {
          setFindings([])
          setIncidentCount(0)
        }
      }
      if (!cancelled && !isBackground) setLoading(false)
    }
    load()
    // Live SOC view: silently refresh every 30s to match the "auto-refresh 30s" badge.
    const refreshIv = setInterval(() => load(true), 30000)
    return () => { cancelled = true; clearInterval(refreshIv) }
  }, [selectedClientId])

  const critical = findings.filter((f) => (f.severity || '').toLowerCase().includes('critical')).length
  const high = findings.filter((f) => (f.severity || '').toLowerCase().includes('high')).length
  React.useEffect(() => {
    if (critical > 0 && setSuggestedWidget) {
      setSuggestedWidget({
        type: 'severity_breakdown',
        message: t('components.cockpitTabs.overview.ai_suggested_widget_message'),
      })
    }
  }, [critical, setSuggestedWidget, t])
  const medium = findings.filter((f) =>
    (f.severity || '').toLowerCase().includes('medium') || (f.severity || '').toLowerCase().includes('med'),
  ).length
  const zeroDayCount = findings.filter((f) => (f.source || '').includes('zero_day')).length
  const score = selectedClientId ? (stats.security_score ?? 0) : 0

  const severityBarData = [
    { name: t('components.cockpitTabs.overview.severity.critical'), count: critical, color: '#ef4444' },
    { name: t('components.cockpitTabs.overview.severity.high'), count: high, color: '#a855f7' },
    { name: t('components.cockpitTabs.overview.severity.medium'), count: medium, color: '#22d3ee' },
  ].filter((d) => d.count > 0)

  const attackSurfaceTargets = stats.attack_surface_targets ?? 0
  const attackSurfacePaths = stats.attack_surface_paths ?? 0
  const attackSurfaceData = [
    {
      labelKey: 'targets_osint',
      label: t('components.cockpitTabs.overview.attack_surface.targets_osint'),
      value: attackSurfaceTargets,
      color: '#22d3ee',
    },
    {
      labelKey: 'paths_wordlist',
      label: t('components.cockpitTabs.overview.attack_surface.paths_wordlist'),
      value: attackSurfacePaths,
      color: '#a855f7',
    },
  ].filter((d) => d.value > 0)
  const attackSurfaceMax = Math.max(attackSurfaceTargets, attackSurfacePaths, 1)

  if (!selectedClientId) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className={`${GLASS_CARD} max-w-md text-center py-12`}>
          <p className="text-white/80 text-sm uppercase tracking-widest mb-2">
            {t('components.cockpitTabs.overview.no_client')}
          </p>
          <p className="text-white/50 text-xs">{t('components.cockpitTabs.overview.select_sidebar')}</p>
        </div>
      </div>
    )
  }

  const clientLabel =
    selectedClient?.name || t('components.cockpitTabs.overview.client_fallback', { id: selectedClientId })

  return (
    <div className="p-6 md:p-8 space-y-6">
      {/* Section header */}
      <div className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-xs font-semibold text-white/60 uppercase tracking-[0.2em] mb-1">
            {t('components.cockpitTabs.overview.title')}
          </h2>
          <p className="text-white/40 text-sm">
            {t('components.cockpitTabs.overview.subtitle', { client: clientLabel })}
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          {t('components.cockpitTabs.overview.live_auto_refresh')}
        </span>
      </div>

      {/* ── Realtime executive layer (Wiz / Falcon / Datadog inspired) ────── */}
      <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-4">
        <SeverityTrendChart />
        <LiveActivityFeed maxHeight={232} />
      </div>

      <MitreCoverageHeatmap />

      <TopMoversPanel />

      {/* AI Suggested visualization (Ollama / Architect) */}
      {suggestedWidget?.message && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-[#22d3ee]/10 border border-[#22d3ee]/30 p-4 flex items-center gap-4"
        >
          <span className="text-2xl">⚡</span>
          <div>
            <p className="text-xs font-semibold text-[#22d3ee] uppercase tracking-wider">
              {t('components.cockpitTabs.overview.ai_suggestion')}
            </p>
            <p className="text-sm text-white/90 mt-0.5">{suggestedWidget.message}</p>
          </div>
        </motion.div>
      )}

      {/* Top row: 4 metric cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              {t('components.cockpitTabs.overview.active_incidents')}
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400/80" />
          </div>
          <p className="text-2xl font-bold text-white mt-1 tabular-nums">
            {loading ? '—' : incidentCount}
          </p>
          <SparklineOrEmpty
            data={trendSpark}
            color="#fbbf24"
            emptyLabel={t('components.cockpitTabs.overview.no_trend')}
          />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              {t('components.cockpitTabs.overview.threat_exposure')}
            </span>
            <ShieldAlert className="w-4 h-4 text-[#22d3ee]/80" />
          </div>
          <p className="text-2xl font-bold text-[#22d3ee] mt-1 tabular-nums">
            {loading ? '—' : stats.total_vulnerabilities}
          </p>
          <SparklineOrEmpty
            data={trendSpark}
            color="#22d3ee"
            emptyLabel={t('components.cockpitTabs.overview.no_trend')}
          />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              {t('components.cockpitTabs.overview.zero_day_risk')}
            </span>
            <Zap className="w-4 h-4 text-[#a855f7]/80" />
          </div>
          <p className="text-2xl font-bold text-[#a855f7] mt-1 tabular-nums">
            {loading ? '—' : zeroDayCount}
          </p>
          <SparklineOrEmpty
            data={zeroDayCount > 0 ? [{ v: zeroDayCount }, { v: zeroDayCount }] : []}
            color="#a855f7"
            emptyLabel={t('components.cockpitTabs.overview.no_zero_day')}
          />
        </div>
        <div className={GLASS_CARD}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-white/50 uppercase tracking-widest">
              {t('components.cockpitTabs.overview.system_health')}
            </span>
            <Activity className="w-4 h-4 text-emerald-400/80" />
          </div>
          <p className="text-2xl font-bold mt-1 tabular-nums" style={{
            color: score >= 70 ? '#4ade80' : score >= 40 ? '#fbbf24' : '#ef4444',
          }}>
            {loading ? '—' : `${score}%`}
          </p>
          <SparklineOrEmpty
            data={resolvedSpark}
            color={score >= 70 ? '#4ade80' : score >= 40 ? '#fbbf24' : '#ef4444'}
            emptyLabel={t('components.cockpitTabs.overview.no_trend')}
          />
        </div>
      </div>

      {/* Center: Gauge + Bar chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className={`${GLASS_CARD} flex flex-col items-center justify-center min-h-[320px]`}>
          <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-4">
            {t('components.cockpitTabs.overview.security_risk_grade')}
          </h3>
          <RiskGauge score={score} />
        </div>
        <div className={`${GLASS_CARD} min-h-[320px]`}>
          <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-4">
            {t('components.cockpitTabs.overview.vulnerabilities_by_severity')}
          </h3>
          {severityBarData.length > 0 ? (
            <div className="h-64 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart accessibilityLayer data={severityBarData} layout="vertical" margin={{ left: 0, right: 20 }}>
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
              {t('components.cockpitTabs.overview.no_severity_data')}
            </div>
          )}
        </div>
      </div>

      {/* Bottom: Attack Surface Growth (OSINT → ASM → path wordlist) */}
      <div className={GLASS_CARD}>
        <h3 className="text-xs font-semibold text-white/50 uppercase tracking-widest mb-6">
          {t('components.cockpitTabs.overview.attack_surface_growth')}
        </h3>
        <div className="space-y-5">
          {attackSurfaceData.length === 0 && !loading && (
            <p className="text-sm text-white/30 text-center py-4">
              {t('components.cockpitTabs.overview.no_attack_surface')}
            </p>
          )}
          {attackSurfaceData.map(({ labelKey, label, value, color }) => (
            <div key={labelKey}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-white/80 flex items-center gap-2">
                  {labelKey.includes('target') && <Globe className="w-4 h-4 text-[#22d3ee]/80" />}
                  {labelKey.includes('path') && <Cloud className="w-4 h-4 text-[#a855f7]/80" />}
                  {label}
                </span>
                <span className="text-xs font-mono text-white/50 tabular-nums">{value}</span>
              </div>
              <div className="h-3 rounded-full bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${Math.round((value / attackSurfaceMax) * 100)}%`,
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
