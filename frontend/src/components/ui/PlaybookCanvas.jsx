import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
  useNodesState,
  useEdgesState,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { cn } from '../../lib/cn'
import NodePalette from './NodePalette.jsx'
import PlaybookNode from './PlaybookNode.jsx'
import PlaybookInspector from './PlaybookInspector.jsx'
import {
  ACTION_KIND_CATALOG,
  makeNode,
  serializeGraph,
  dslToFlow,
  flowToDsl,
  logicalPlaybookKey,
  nextNumericId,
  canConnect,
  connect,
  autoConnectNewNode,
  patchNode,
  removeNode,
  removeEdge,
  isTriggerNode,
  nodeTitleKey,
  summarizeTrigger,
  summarizeAction,
  readNodeDragType,
} from '../../lib/playbookFlow.js'

const NODE_ACCENT = {
  trigger: 'border-accent-cyan/50',
  action: 'border-accent-violet/50',
  condition: 'border-severity-medium/50',
  delay: 'border-border-strong',
  notify: 'border-severity-info/50',
}

const HANDLE_CLASS = '!size-2.5 !border-2 !border-bg-1 !bg-border-strong'

function minimapColor(node) {
  const t = node.data?.nodeType
  if (t === 'trigger') return '#22d3ee'
  if (t === 'notify') return '#38bdf8'
  if (t === 'condition') return '#f59e0b'
  return '#8b5cf6'
}

/** Custom @xyflow node rendered with PlaybookNode + connect handles. */
function FlowPlaybookNode({ data, selected }) {
  const { t } = useTranslation()
  const nodeType = data?.nodeType || 'action'
  const isCondition = nodeType === 'condition'
  const isTrigger = nodeType === 'trigger' || data?.kind === 'trigger'
  const title = t(nodeTitleKey(data))
  const summary = isTrigger
    ? summarizeTrigger(data?.trigger, t('playbooks.severity_any_short'))
    : (data?.summary ?? summarizeAction(data?.kind, data?.params))

  return (
    <div className={cn('relative', selected && 'z-10')}>
      {!isTrigger && (
        <Handle type="target" position={Position.Top} className={HANDLE_CLASS} />
      )}
      <PlaybookNode
        type={nodeType}
        title={title}
        summary={summary || undefined}
        selected={selected}
        typeLabel={t(`playbooks.nodes.${nodeType}`)}
        showPorts={false}
        className={NODE_ACCENT[nodeType]}
      />
      {isCondition ? (
        <>
          <Handle
            type="source"
            position={Position.Bottom}
            id="true"
            className={cn(HANDLE_CLASS, '!bg-status-active')}
            style={{ insetInlineStart: '33%' }}
          />
          <Handle
            type="source"
            position={Position.Bottom}
            id="false"
            className={cn(HANDLE_CLASS, '!bg-severity-critical')}
            style={{ insetInlineStart: '66%' }}
          />
        </>
      ) : (
        <Handle type="source" position={Position.Bottom} className={HANDLE_CLASS} />
      )}
    </div>
  )
}

const nodeTypes = { playbook: FlowPlaybookNode }

const defaultEdgeOptions = {
  animated: true,
  markerEnd: { type: MarkerType.ArrowClosed, color: '#22d3ee' },
  style: { stroke: '#22d3ee', strokeWidth: 1.6 },
}

function CanvasInner({
  initialNodes = [],
  initialEdges = [],
  trigger,
  actions,
  onChange,
  onDslChange,
  height = 360,
  className,
  showPalette = true,
  showInspector = true,
  paletteTypes,
}) {
  const { t, i18n } = useTranslation()
  const soarMode = trigger !== undefined || typeof onDslChange === 'function'
  const seed = useMemo(
    () => (soarMode ? dslToFlow(trigger, actions) : { nodes: initialNodes, edges: initialEdges }),
    // Seed only for the first paint; hydration below reacts to logical DSL changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  )
  const [nodes, setNodes, onNodesChange] = useNodesState(seed.nodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(seed.edges)
  const [selectedNodeId, setSelectedNodeId] = useState(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState(null)
  const lastLogical = useRef(soarMode ? logicalPlaybookKey(trigger, actions) : '')
  const pendingConnectId = useRef(null)
  const wrapperRef = useRef(null)
  const { screenToFlowPosition, fitView } = useReactFlow()
  const screenToFlowPositionRef = useRef(screenToFlowPosition)
  const fitViewRef = useRef(fitView)
  screenToFlowPositionRef.current = screenToFlowPosition
  fitViewRef.current = fitView
  const rtl = (i18n.dir?.() || i18n.language) === 'rtl' || i18n.language === 'he'
  const onChangeRef = useRef(onChange)
  const onDslChangeRef = useRef(onDslChange)
  onChangeRef.current = onChange
  onDslChangeRef.current = onDslChange

  const resolvedPalette = useMemo(() => {
    if (paletteTypes) return paletteTypes
    if (!soarMode) return undefined
    return [
      {
        type: 'trigger',
        nodeType: 'trigger',
        label: t('playbooks.nodes.trigger'),
        description: t('playbooks.nodes.trigger_desc'),
        ariaLabel: t('playbooks.palette.add', { type: t('playbooks.nodes.trigger') }),
      },
      ...ACTION_KIND_CATALOG.map((k) => {
        const label = t(`playbooks.action.${k.kind}`)
        return {
          type: k.kind,
          nodeType: k.nodeType,
          label,
          description: t(`playbooks.action.${k.kind}_desc`),
          ariaLabel: t('playbooks.palette.add', { type: label }),
        }
      }),
    ]
  }, [paletteTypes, soarMode, t])

  useEffect(() => {
    if (!soarMode) return
    const key = logicalPlaybookKey(trigger, actions)
    if (key === lastLogical.current) return
    lastLogical.current = key
    pendingConnectId.current = null
    const next = dslToFlow(trigger, actions)
    setNodes(next.nodes)
    setEdges(next.edges)
    requestAnimationFrame(() => {
      try {
        fitViewRef.current?.({ padding: 0.2, duration: 180 })
      } catch {
        /* canvas unmounted */
      }
    })
  }, [soarMode, trigger, actions, setNodes, setEdges])

  useEffect(() => {
    onChangeRef.current?.(serializeGraph(nodes, edges))
    if (!onDslChangeRef.current) return
    const dsl = flowToDsl(nodes, edges)
    lastLogical.current = logicalPlaybookKey(dsl.trigger, dsl.actions)
    onDslChangeRef.current(dsl)
  }, [nodes, edges])

  const onConnect = useCallback(
    (params) => {
      const source = params.source || params.from
      const target = params.target || params.to
      setEdges((eds) => {
        if (!canConnect(nodes, eds, source, target)) return eds
        return connect(eds, source, target, {
          ...defaultEdgeOptions,
          ...(params.sourceHandle ? { sourceHandle: params.sourceHandle } : {}),
          ...(params.targetHandle ? { targetHandle: params.targetHandle } : {}),
        })
      })
    },
    [nodes, setEdges],
  )

  const isValidConnection = useCallback(
    (conn) => canConnect(nodes, edges, conn.source || conn.from, conn.target || conn.to),
    [nodes, edges],
  )

  const onBeforeDelete = useCallback(({ nodes: doomed, edges: doomedEdges }) => {
    if (!doomed?.some(isTriggerNode)) return true
    const nodesToDelete = doomed.filter((n) => !isTriggerNode(n))
    const deletedIds = new Set(nodesToDelete.map((n) => n.id))
    const edgesToDelete = (doomedEdges || []).filter(
      (e) => deletedIds.has(e.source) || deletedIds.has(e.target),
    )
    return { nodes: nodesToDelete, edges: edgesToDelete }
  }, [])

  const addNodeOfType = useCallback(
    (type, position) => {
      setNodes((nds) => {
        if (type === 'trigger' && nds.some(isTriggerNode)) return nds
        const node = makeNode(type, nextNumericId(nds), position)
        pendingConnectId.current = node.id
        setSelectedNodeId(node.id)
        setSelectedEdgeId(null)
        return [...nds.map((n) => ({ ...n, selected: false })), { ...node, selected: true }]
      })
    },
    [setNodes],
  )

  useEffect(() => {
    const id = pendingConnectId.current
    if (!id) return
    pendingConnectId.current = null
    setEdges((eds) => autoConnectNewNode(nodes, eds, id))
  }, [nodes, setEdges])

  const onDrop = useCallback(
    (e) => {
      e.preventDefault()
      const type = readNodeDragType(e.dataTransfer)
      if (!type) return
      let position = { x: e.clientX, y: e.clientY }
      try {
        position = screenToFlowPositionRef.current({ x: e.clientX, y: e.clientY })
      } catch {
        const bounds = wrapperRef.current?.getBoundingClientRect?.() || { left: 0, top: 0 }
        position = { x: e.clientX - bounds.left, y: e.clientY - bounds.top }
      }
      addNodeOfType(type, position)
    },
    [addNodeOfType],
  )

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || null
  const selectedEdge = edges.find((e) => e.id === selectedEdgeId) || null

  const onSelectionChange = useCallback(({ nodes: sn, edges: se }) => {
    setSelectedNodeId(sn?.[0]?.id || null)
    setSelectedEdgeId(se?.[0]?.id || null)
  }, [])

  const handlePatchNode = useCallback(
    (id, dataPatch) => {
      setNodes((nds) => patchNode(nds, id, dataPatch))
    },
    [setNodes],
  )

  const handleDeleteNode = useCallback(
    (id) => {
      setNodes((nds) => {
        const target = nds.find((n) => n.id === id)
        if (isTriggerNode(target)) return nds
        const out = removeNode(nds, edges, id)
        setEdges(out.edges)
        return out.nodes
      })
      setSelectedNodeId(null)
    },
    [edges, setEdges, setNodes],
  )

  const handleDeleteEdge = useCallback(
    (id) => {
      setEdges((eds) => removeEdge(eds, id))
      setSelectedEdgeId(null)
    },
    [setEdges],
  )

  const issues = useMemo(() => (soarMode ? flowToDsl(nodes, edges).issues : []), [soarMode, nodes, edges])

  const canvasLabel = t('playbooks.canvas.label')
  const emptyHint = t('playbooks.canvas.empty')

  return (
    <div className={cn('grid gap-3 lg:grid-cols-[11rem_minmax(0,1fr)_16rem]', !showInspector && 'lg:grid-cols-[11rem_minmax(0,1fr)]', className)}>
      {showPalette && (
        <NodePalette
          types={resolvedPalette}
          onAdd={(typ) => addNodeOfType(typ, { x: 80, y: 48 + nodes.length * 24 })}
          aria-label={t('playbooks.palette.group')}
        />
      )}
      <div className="flex min-w-0 flex-col gap-2">
        {issues.some((i) => i.level === 'error' || i.level === 'warning') && (
          <ul className="space-y-1 text-[11px]" aria-live="polite">
            {issues.map((issue) => (
              <li
                key={issue.code}
                className={issue.level === 'error' ? 'text-rose-300' : 'text-amber-200/90'}
              >
                {t(`playbooks.canvas.issue_${issue.code}`, { count: issue.count || 0 })}
              </li>
            ))}
          </ul>
        )}
        <div
          ref={wrapperRef}
          onDrop={onDrop}
          onDragOver={(e) => {
            e.preventDefault()
            if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'
          }}
          aria-label={canvasLabel}
          className="playbook-flow relative overflow-hidden rounded-xl border border-border-default bg-bg-1"
          style={{ height }}
        >
          {nodes.length === 0 && (
            <p className="pointer-events-none absolute inset-x-4 top-4 z-10 text-center text-[12px] text-text-muted">
              {emptyHint}
            </p>
          )}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            isValidConnection={isValidConnection}
            onBeforeDelete={onBeforeDelete}
            onSelectionChange={onSelectionChange}
            defaultEdgeOptions={defaultEdgeOptions}
            fitView
            colorMode="dark"
            deleteKeyCode={['Backspace', 'Delete']}
            proOptions={{ hideAttribution: true }}
            className={rtl ? 'playbook-flow--rtl' : undefined}
          >
            <Background color="#1e293b" gap={18} />
            <Controls showInteractive={false} position={rtl ? 'bottom-right' : 'bottom-left'} />
            <MiniMap
              nodeColor={minimapColor}
              maskColor="rgba(2,6,23,0.7)"
              pannable
              zoomable
              position={rtl ? 'bottom-left' : 'bottom-right'}
            />
          </ReactFlow>
        </div>
      </div>
      {showInspector && (
        <PlaybookInspector
          node={selectedNode}
          edge={selectedEdge && !selectedNode ? selectedEdge : null}
          onPatchNode={handlePatchNode}
          onDeleteNode={handleDeleteNode}
          onDeleteEdge={handleDeleteEdge}
        />
      )}
    </div>
  )
}

/**
 * PlaybookCanvas — an editable SOAR playbook flow editor on @xyflow. Drag node
 * types from the palette onto the canvas (or click to add), wire them by
 * dragging between handles, configure the selected node, and persist the
 * linear `when {trigger} do [actions]` DSL via `onDslChange`.
 *
 * Graph-only mode (design-system gallery): pass `initialNodes` / `onChange`.
 * DSL mode (Command Center builder): pass `trigger`, `actions`, `onDslChange`.
 */
export default function PlaybookCanvas(props) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  )
}

export { PlaybookCanvas }
