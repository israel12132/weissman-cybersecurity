import React, { useCallback, useEffect, useState } from 'react'
import { ComposableMap, Geographies, Geography, ZoomableGroup, Marker } from 'react-simple-maps'
import { Radio, RefreshCw } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

function fallbackCoord(region, pop) {
  const r = `${region} ${pop}`.toLowerCase()
  if (r.includes('eu') || r.includes('fra') || r.includes('ams')) return [50.11, 8.68]
  if (r.includes('asia') || r.includes('tok') || r.includes('sin')) return [1.35, 103.82]
  if (r.includes('uk') || r.includes('lhr')) return [51.47, -0.4543]
  if (r.includes('syd') || r.includes('au')) return [-33.86, 151.2]
  if (r.includes('us-east') || r.includes('iad')) return [39.04, -77.49]
  if (r.includes('us-west') || r.includes('sfo') || r.includes('lax')) return [37.77, -122.42]
  const h = (region + pop).split('').reduce((a, c) => a + c.charCodeAt(0), 0)
  return [20 + (h % 40) - 20, -30 + (h % 80) - 40]
}

export default function GlobalEdgeSwarmMap() {
  const [nodes, setNodes] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [manifest, setManifest] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [nr, mr] = await Promise.all([
        apiFetch('/api/edge-swarm/nodes'),
        apiFetch('/api/edge-fuzz/manifest'),
      ])
      const nd = nr.ok ? await nr.json() : { nodes: [] }
      setNodes(Array.isArray(nd.nodes) ? nd.nodes : [])
      if (mr.ok) setManifest(await mr.json())
      else setManifest(null)
    } catch (e) {
      setError('Failed to load edge swarm')
      setNodes([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 45000)
    return () => clearInterval(t)
  }, [load])

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6 min-h-[420px]">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Radio className="w-5 h-5 text-violet-400" />
          <div>
            <h2 className="text-lg font-semibold text-white tracking-wide">Global edge swarm</h2>
            <p className="text-xs text-white/50 max-w-xl">
              WASM fuzz payload nodes (`fuzz_core`, wasm32-unknown-unknown). Workers register via{' '}
              <code className="text-violet-300/90">POST /api/edge-swarm/heartbeat</code> — bypasses regional choke points when deployed to Cloudflare / Lambda@Edge.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-violet-500/40 bg-violet-950/40 text-violet-200 text-sm hover:bg-violet-900/50 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {manifest && (
        <div className="text-[11px] font-mono text-white/40 border border-white/10 rounded-lg px-3 py-2 bg-black/30">
          Crate: {manifest.crate ?? 'fuzz_core'} · target: {manifest.rust_target ?? 'wasm32-unknown-unknown'} · build:{' '}
          {manifest.build_command ?? 'scripts/build_fuzz_wasm.sh'}
        </div>
      )}

      {error && <div className="text-sm text-red-400">{error}</div>}

      <div className="flex-1 rounded-2xl border border-white/10 bg-slate-950/90 overflow-hidden min-h-[320px]">
        <ComposableMap
          projectionConfig={{ scale: 140 }}
          style={{ width: '100%', height: '100%', minHeight: 320 }}
        >
          <ZoomableGroup center={[20, 0]} zoom={0.85}>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="rgba(30,30,40,0.9)"
                    stroke="rgba(139,92,246,0.25)"
                    strokeWidth={0.4}
                  />
                ))
              }
            </Geographies>
            {nodes.map((n) => {
              const lat = n.latitude != null ? n.latitude : fallbackCoord(n.region_code || '', n.pop_label || '')[0]
              const lng = n.longitude != null ? n.longitude : fallbackCoord(n.region_code || '', n.pop_label || '')[1]
              const jobs = n.active_jobs ?? 0
              return (
                <Marker key={n.id} coordinates={[lng, lat]}>
                  <circle r={6 + Math.min(jobs, 8)} fill="rgba(167,139,250,0.95)" stroke="#fff" strokeWidth={1} />
                  <text textAnchor="middle" y={-12} fill="rgba(221,214,254,0.95)" fontSize={9} style={{ fontFamily: 'ui-monospace, monospace' }}>
                    {n.pop_label || n.region_code || 'POP'}
                  </text>
                </Marker>
              )
            })}
          </ZoomableGroup>
        </ComposableMap>
      </div>

      {nodes.length === 0 && !loading && (
        <p className="text-sm text-white/45">
          No edge nodes registered. From a worker, POST{' '}
          <code className="text-cyan-300/90">region_code</code>, <code className="text-cyan-300/90">pop_label</code>, optional lat/lng and{' '}
          <code className="text-cyan-300/90">wasm_revision</code>.
        </p>
      )}

      {nodes.length > 0 && (
        <ul className="grid gap-2 sm:grid-cols-2 text-xs text-white/70">
          {nodes.map((n) => (
            <li key={n.id} className="border border-white/10 rounded-lg px-3 py-2 bg-black/30 font-mono">
              <span className="text-violet-300">{n.region_code}</span> · {n.pop_label}{' '}
              <span className="text-white/40">jobs={n.active_jobs ?? 0}</span>{' '}
              {n.provider && <span className="text-white/35">· {n.provider}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
