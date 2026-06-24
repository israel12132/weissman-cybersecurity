import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { GitBranch, Target, AlertTriangle, Shield, Download, Maximize2 } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid, SkeletonBar } from '../components/ui/Skeleton'
import { api } from '../utils/apiFetch';
import { useFirstTenantClientId, withClientId } from '../lib/aliasClient';

const NS = 'pages.riskGraphVisualization';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
};

function getSeverityColor(severity) {
  return SEVERITY_COLORS[severity?.toLowerCase()] ?? '#6b7280';
}

function severityLabel(severity, t) {
  const s = String(severity ?? 'medium').toLowerCase();
  return t(`${NS}.severity_${s}`, { defaultValue: s });
}

function exportNodesCsv(nodes) {
  const header = ['id', 'name', 'severity', 'risk_score', 'node_type', 'is_choke_point'];
  const rows = nodes.map((n) => [
    n.id ?? '',
    (n.name || n.label || '').replace(/"/g, '""'),
    n.severity ?? '',
    n.risk_score ?? '',
    n.node_type ?? '',
    n.is_choke_point ? 'yes' : 'no',
  ]);
  const csv = [header.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `risk-graph-nodes-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Simple force-directed layout (no external deps). */
function computeForceLayout(nodes, edges, width, height, layout) {
  if (!nodes.length) return [];

  const positions = nodes.map((node, i) => {
    if (layout === 'circular') {
      const angle = (i / nodes.length) * Math.PI * 2;
      const r = Math.min(width, height) * 0.35;
      return {
        ...node,
        x: width / 2 + Math.cos(angle) * r,
        y: height / 2 + Math.sin(angle) * r,
        vx: 0,
        vy: 0,
      };
    }
    if (layout === 'hierarchical') {
      const cols = Math.ceil(Math.sqrt(nodes.length));
      const col = i % cols;
      const row = Math.floor(i / cols);
      return {
        ...node,
        x: (col + 0.5) * (width / cols),
        y: (row + 0.5) * (height / Math.ceil(nodes.length / cols)),
        vx: 0,
        vy: 0,
      };
    }
    return {
      ...node,
      x: width / 2 + (Math.random() - 0.5) * width * 0.6,
      y: height / 2 + (Math.random() - 0.5) * height * 0.6,
      vx: 0,
      vy: 0,
    };
  });

  if (layout !== 'force' || nodes.length < 2) return positions;

  const idIndex = new Map(positions.map((n, idx) => [String(n.id), idx]));
  const linkList = edges
    .map((e) => ({
      source: idIndex.get(String(e.source)),
      target: idIndex.get(String(e.target)),
    }))
    .filter((l) => l.source != null && l.target != null);

  const cx = width / 2;
  const cy = height / 2;
  const iterations = Math.min(120, 40 + nodes.length * 4);

  for (let iter = 0; iter < iterations; iter += 1) {
    const alpha = 1 - iter / iterations;
    for (let i = 0; i < positions.length; i += 1) {
      for (let j = i + 1; j < positions.length; j += 1) {
        let dx = positions[j].x - positions[i].x;
        let dy = positions[j].y - positions[i].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const repulse = (8000 * alpha) / (dist * dist);
        dx = (dx / dist) * repulse;
        dy = (dy / dist) * repulse;
        positions[i].vx -= dx;
        positions[i].vy -= dy;
        positions[j].vx += dx;
        positions[j].vy += dy;
      }
    }
    for (const link of linkList) {
      const a = positions[link.source];
      const b = positions[link.target];
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - 120) * 0.04 * alpha;
      dx = (dx / dist) * force;
      dy = (dy / dist) * force;
      a.vx += dx;
      a.vy += dy;
      b.vx -= dx;
      b.vy -= dy;
    }
    for (const p of positions) {
      p.vx += (cx - p.x) * 0.002 * alpha;
      p.vy += (cy - p.y) * 0.002 * alpha;
      p.vx *= 0.85;
      p.vy *= 0.85;
      p.x += p.vx;
      p.y += p.vy;
      p.x = Math.max(40, Math.min(width - 40, p.x));
      p.y = Math.max(40, Math.min(height - 40, p.y));
    }
  }

  return positions.map(({ vx, vy, ...rest }) => rest);
}

function nodeRadius(node) {
  return 12 + Math.min(18, (node.risk_score || 0) / 5);
}

const FILTER_KEYS = {
  all: `${NS}.filter_all`,
  critical: `${NS}.filter_critical`,
  high: `${NS}.filter_high`,
  medium: `${NS}.filter_medium`,
  low: `${NS}.filter_low`,
};

/**
 * RiskGraphVisualization - Interactive attack path and risk visualization
 */
export default function RiskGraphVisualization() {
  const { t } = useTranslation();
  const { clientId, loading: clientLoading } = useFirstTenantClientId();
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [attackPaths, setAttackPaths] = useState(null);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filter, setFilter] = useState('all');
  const [layout, setLayout] = useState('force');
  const canvasRef = useRef(null);
  const positionsRef = useRef([]);

  useEffect(() => {
    if (clientLoading) return;
    if (clientId == null) {
      setGraphData({ nodes: [], edges: [] });
      setLoading(false);
      return;
    }
    fetchGraphData(clientId);
  }, [clientId, clientLoading]);

  const filteredNodes = useMemo(() => {
    if (filter === 'all') return graphData.nodes;
    return graphData.nodes.filter((n) => n.severity === filter);
  }, [graphData.nodes, filter]);

  const filteredNodeIds = useMemo(
    () => new Set(filteredNodes.map((n) => String(n.id))),
    [filteredNodes],
  );

  const filteredEdges = useMemo(
    () => graphData.edges.filter(
      (e) => filteredNodeIds.has(String(e.source)) && filteredNodeIds.has(String(e.target)),
    ),
    [graphData.edges, filteredNodeIds],
  );

  const listFindings = useMemo(() => graphData.nodes.map((n) => ({
    id: n.id,
    severity: n.severity || 'medium',
    title: n.name || n.label || n.id,
    type: n.node_type || 'node',
    description: String(n.risk_score ?? ''),
    resource: n.is_choke_point ? 'choke_point' : '',
  })), [graphData.nodes])

  const { exportCsv, filteredFindings, searchQuery, setSearchQuery } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-risk-graph',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const searchFilteredNodes = useMemo(() => {
    if (!searchQuery.trim()) return filteredNodes
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return filteredNodes.filter((n) => ids.has(String(n.id)))
  }, [filteredNodes, filteredFindings, searchQuery])

  const searchFilteredNodeIds = useMemo(
    () => new Set(searchFilteredNodes.map((n) => String(n.id))),
    [searchFilteredNodes],
  )

  const searchFilteredEdges = useMemo(
    () => filteredEdges.filter(
      (e) => searchFilteredNodeIds.has(String(e.source)) && searchFilteredNodeIds.has(String(e.target)),
    ),
    [filteredEdges, searchFilteredNodeIds],
  )

  const fetchGraphData = async (cid) => {
    try {
      setLoading(true);
      setPathsLoading(true);
      const [graphRes, pathsRes] = await Promise.all([
        api.get(withClientId('/api/risk/graph', cid)),
        api.get(`/api/attack-paths/${cid}`).catch(() => null),
      ]);
      setGraphData(graphRes);
      setSelectedNode(null);
      if (pathsRes?.snapshot) {
        setAttackPaths(pathsRes.snapshot);
      } else {
        setAttackPaths(null);
      }
    } catch (error) {
      console.error('Failed to fetch graph data:', error);
      setGraphData({ nodes: [], edges: [] });
      setAttackPaths(null);
    } finally {
      setLoading(false);
      setPathsLoading(false);
    }
  };

  const recomputeAttackPaths = async () => {
    if (clientId == null) return;
    setPathsLoading(true);
    try {
      const res = await api.get(`/api/attack-paths/${clientId}?recompute=1`);
      setAttackPaths(res?.snapshot ?? null);
    } catch (e) {
      console.error('Attack path recompute failed:', e);
    } finally {
      setPathsLoading(false);
    }
  };

  const renderGraph = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.offsetWidth;
    const height = canvas.height = canvas.offsetHeight;

    ctx.fillStyle = '#09090b';
    ctx.fillRect(0, 0, width, height);

    if (!searchFilteredNodes.length) return;

    const nodePositions = computeForceLayout(searchFilteredNodes, searchFilteredEdges, width, height, layout);
    positionsRef.current = nodePositions;
    const posById = new Map(nodePositions.map((n) => [String(n.id), n]));

    searchFilteredEdges.forEach((edge) => {
      const source = posById.get(String(edge.source));
      const target = posById.get(String(edge.target));
      if (!source || !target) return;
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = edge.critical ? '#ef444480' : '#334155';
      ctx.lineWidth = edge.critical ? 3 : 2;
      ctx.stroke();
    });

    nodePositions.forEach((node) => {
      const color = getSeverityColor(node.severity);
      const radius = nodeRadius(node);
      const isSelected = selectedNode && String(selectedNode.id) === String(node.id);

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = isSelected ? '#ffffff' : '#ffffff40';
      ctx.lineWidth = isSelected ? 3 : 2;
      ctx.stroke();

      ctx.fillStyle = '#fff';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      const label = node.name || node.label || t('pages.riskGraphVisualization.asset_fallback');
      ctx.fillText(label.length > 24 ? `${label.slice(0, 22)}…` : label, node.x, node.y + radius + 14);
    });
  }, [searchFilteredNodes, searchFilteredEdges, layout, selectedNode, t]);

  useEffect(() => {
    renderGraph();
  }, [renderGraph]);

  useEffect(() => {
    const onResize = () => renderGraph();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [renderGraph]);

  const handleCanvasClick = (event) => {
    const canvas = canvasRef.current;
    if (!canvas || !positionsRef.current.length) return;
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    let hit = null;
    let bestDist = Infinity;
    for (const node of positionsRef.current) {
      const r = nodeRadius(node);
      const dx = x - node.x;
      const dy = y - node.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist <= r + 4 && dist < bestDist) {
        bestDist = dist;
        hit = node;
      }
    }
    setSelectedNode(hit);
  };

  const exportGraph = (format) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (format === 'png') {
      const url = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = 'risk-graph.png';
      link.href = url;
      link.click();
    }
  };

  const stats = {
    totalAssets: graphData.nodes.length,
    criticalPaths: graphData.edges.filter((e) => e.critical).length,
    highRisk: graphData.nodes.filter((n) => n.severity === 'critical' || n.severity === 'high').length,
    avgRiskScore: graphData.nodes.length > 0
      ? (graphData.nodes.reduce((sum, n) => sum + (n.risk_score || 0), 0) / graphData.nodes.length).toFixed(1)
      : 0,
  };

  const meta = selectedNode?.metadata && typeof selectedNode.metadata === 'object'
    ? selectedNode.metadata
    : {};

  const reloadGraph = () => {
    if (clientId) fetchGraphData(clientId)
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      icon={<GitBranch />}
      actions={(
        <ShellScanActions
          onRefresh={reloadGraph}
          onExport={() => exportNodesCsv(graphData.nodes)}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && graphData.nodes.length === 0 ? (
          <SkeletonWidgetGrid count={4} />
        ) : (
        <>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.riskGraphVisualization.total_assets')}</span>
              <Target className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.totalAssets}</div>
          </div>
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.riskGraphVisualization.critical_paths')}</span>
              <GitBranch className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.criticalPaths}</div>
          </div>
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.riskGraphVisualization.high_risk_assets')}</span>
              <AlertTriangle className="w-4 h-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-orange-400">{stats.highRisk}</div>
          </div>
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.riskGraphVisualization.avg_risk_score')}</span>
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.avgRiskScore}</div>
          </div>
        </div>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3 flex-wrap flex-1 min-w-0">
            {graphData.nodes.length > 0 && (
              <WeissmanListToolbar
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
                resultCount={searchFilteredNodes.length}
                totalCount={filteredNodes.length}
                className="flex-1 min-w-[280px]"
              />
            )}
            <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
              {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    filter === f
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  {t(FILTER_KEYS[f])}
                </button>
              ))}
            </div>
            <select
              value={layout}
              onChange={(e) => setLayout(e.target.value)}
              className="px-3 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="force">{t('pages.riskGraphVisualization.layout_force')}</option>
              <option value="hierarchical">{t('pages.riskGraphVisualization.layout_hierarchical')}</option>
              <option value="circular">{t('pages.riskGraphVisualization.layout_circular')}</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => exportNodesCsv(graphData.nodes)}
              disabled={graphData.nodes.length === 0}
              className="flex items-center gap-2 px-3 py-2 bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 rounded-lg text-sm font-medium hover:bg-emerald-500/25 transition-colors disabled:opacity-40"
            >
              <Download className="w-4 h-4" />
              {t(`${NS}.export_csv`)}
            </button>
            <button
              type="button"
              onClick={() => exportGraph('png')}
              className="flex items-center gap-2 px-3 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-colors"
            >
              <Download className="w-4 h-4" />
              {t('pages.riskGraphVisualization.export_png')}
            </button>
            <button
              type="button"
              onClick={() => setSelectedNode(null)}
              className="flex items-center gap-2 px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium text-gray-300 hover:bg-white/10 transition-colors"
            >
              <Maximize2 className="w-4 h-4" />
              {t('pages.riskGraphVisualization.reset_view')}
            </button>
          </div>
        </div>

        {/* Dijkstra attack paths — internet_exposed → crown_jewel (EPSS/CVSS weighted) */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between gap-3 flex-wrap mb-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              {t(`${NS}.attack_paths_heading`)}
            </h3>
            <button
              type="button"
              onClick={recomputeAttackPaths}
              disabled={pathsLoading || clientId == null}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 disabled:opacity-40"
            >
              {pathsLoading ? t(`${NS}.loading`) : t(`${NS}.recompute_paths`)}
            </button>
          </div>
          {pathsLoading && !attackPaths ? (
            <div className="space-y-2">
              <SkeletonBar className="h-12 w-full" />
              <SkeletonBar className="h-12 w-5/6" />
            </div>
          ) : !attackPaths?.paths?.length ? (
            <p className="text-sm text-gray-500">
              {t(`${NS}.no_attack_paths`)}
            </p>
          ) : (
            <div className="space-y-3 max-h-80 overflow-y-auto">
              {attackPaths.paths.slice(0, 8).map((path, idx) => (
                <div key={idx} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                  <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
                    <span>{t(`${NS}.path_label`, { num: idx + 1, hops: path.hops })}</span>
                    <span className="text-red-300 font-mono">
                      {t(`${NS}.path_risk`, { value: path.risk?.toFixed?.(1) ?? path.risk })}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-white/70 line-clamp-2">
                    {(path.steps || []).map((s) => s.label || s.graph_key).filter(Boolean).join(' → ')}
                  </p>
                </div>
              ))}
              {attackPaths.choke_points?.length > 0 && (
                <div className="pt-2 border-t border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-amber-400/80 mb-2">
                    {t(`${NS}.choke_points`)}
                  </p>
                  {attackPaths.choke_points.slice(0, 5).map((cp) => (
                    <div key={cp.node_id} className="text-[11px] text-white/60 flex justify-between gap-2 py-0.5">
                      <span className="truncate">{cp.label || cp.graph_key}</span>
                      <span className="text-amber-300 shrink-0">{t(`${NS}.path_coverage`, { pct: cp.coverage_pct })}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="grid lg:grid-cols-[1fr_320px] gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-white/10">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-cyan-400" />
                {t('pages.riskGraphVisualization.graph_heading')}
              </h3>
            </div>
            <div className="relative">
              {loading ? (
                <div className="h-[600px] flex items-center justify-center p-6">
                  <SkeletonBar className="h-full w-full rounded-none" />
                </div>
              ) : graphData.nodes.length === 0 ? (
                <div className="h-[600px] flex items-center justify-center p-6">
                  <EmptyState
                    icon="shield"
                    title={t('pages.riskGraphVisualization.empty_title')}
                    body={t('pages.riskGraphVisualization.empty_body')}
                  />
                </div>
              ) : searchFilteredNodes.length === 0 ? (
                <div className="h-[600px] flex items-center justify-center p-6">
                  <EmptyState
                    icon="search"
                    title={t('weissmanFindings.filtered_title')}
                    body={t('weissmanFindings.filtered_body')}
                  />
                </div>
              ) : (
                <canvas
                  ref={canvasRef}
                  className="w-full h-[600px] cursor-pointer"
                  onClick={handleCanvasClick}
                />
              )}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-5 min-h-[200px]">
            <h3 className="text-sm font-semibold text-white mb-4">{t('pages.riskGraphVisualization.node_detail')}</h3>
            {!selectedNode ? (
              <p className="text-xs text-gray-500">{t('pages.riskGraphVisualization.node_hint')}</p>
            ) : (
              <div className="space-y-4">
                <div>
                  <h4 className="text-base font-bold text-white">{selectedNode.name}</h4>
                  <p className="text-xs text-gray-400 mt-1">
                    {selectedNode.description || meta.description || meta.summary || t('pages.riskGraphVisualization.no_description')}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="text-xs text-gray-400 block">{t('pages.riskGraphVisualization.risk_score')}</span>
                    <span className="text-lg font-bold text-white">{selectedNode.risk_score ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400 block">{t('pages.riskGraphVisualization.severity')}</span>
                    <span className="text-lg font-bold" style={{ color: getSeverityColor(selectedNode.severity) }}>
                      {severityLabel(selectedNode.severity, t)}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400 block">{t('pages.riskGraphVisualization.type')}</span>
                    <span className="text-white">{selectedNode.node_type || '—'}</span>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400 block">{t('pages.riskGraphVisualization.choke_point')}</span>
                    <span className="text-white">{selectedNode.is_choke_point ? t('common.yes') : t('common.no')}</span>
                  </div>
                </div>
                {(selectedNode.finding_id || meta.finding_id || meta.vulnerability_id) && (
                  <div className="rounded-lg bg-cyan-500/5 border border-cyan-500/20 p-3">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400/70 mb-1">{t('pages.riskGraphVisualization.linked_finding')}</div>
                    <div className="text-xs font-mono text-white/80">
                      {t('pages.riskGraphVisualization.id_label', { id: selectedNode.finding_id || meta.finding_id || meta.vulnerability_id })}
                    </div>
                    {meta.title && <div className="text-xs text-white/60 mt-1">{meta.title}</div>}
                    {meta.mitre && <div className="text-[10px] font-mono text-white/40 mt-1">{t('pages.riskGraphVisualization.mitre_label', { mitre: meta.mitre })}</div>}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">{t('pages.riskGraphVisualization.legend')}</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
              <div key={sev} className="flex items-center gap-3">
                <div className="w-4 h-4 rounded-full" style={{ background: color }} />
                <span className="text-sm text-gray-300">{t(`${NS}.risk_label`, { severity: severityLabel(sev, t) })}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 text-xs text-gray-500">
            {t(`${NS}.legend_hint`)}
          </div>
        </div>
        </>
        )}
      </div>
    </PageShell>
  );
}
