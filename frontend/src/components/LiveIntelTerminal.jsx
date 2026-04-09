import { useEffect, useRef, useState } from 'react'
import { FixedSizeList as List } from 'react-window'

function severityColor(severity) {
  const s = (severity || '').toLowerCase()
  if (s === 'critical') return 'text-red-400'
  if (s === 'high') return 'text-amber-400'
  if (s === 'medium') return 'text-yellow-500/90'
  return 'text-emerald-400'
}

function parseEvent(e) {
  const target = e.target || e.target_ip || e.targetUrl || '—'
  const severity = e.severity || (e.message && /critical|high|medium|low/i.exec(e.message)?.[0]) || 'INFO'
  const action = e.message || e.action || e.agentId || '—'
  const time = e.time || e.timestamp || '--:--:--'
  return { id: e.id, time: String(time).slice(-8), target, severity, action }
}

const ROW_HEIGHT = 24

const IDLE_ONLINE = 'SYSTEM ARMED: AWAITING LIVE TELEMETRY'
const IDLE_OFFLINE = 'CONNECTION LOST — Reconnecting...'
const IDLE_MONITORING = 'Monitoring infrastructure...'

export default function LiveIntelTerminal({ events, highlightedEventId, connectionStatus, matrixStyle = false }) {
  const listRef = useRef(null)
  const containerRef = useRef(null)
  const [listHeight, setListHeight] = useState(400)
  const parsed = (events || []).map(parseEvent)
  const isOnline = connectionStatus === 'online'
  const idleMessage = isOnline ? IDLE_ONLINE : IDLE_OFFLINE

  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(() => {
      if (containerRef.current) setListHeight(containerRef.current.clientHeight)
    })
    ro.observe(containerRef.current)
    setListHeight(containerRef.current.clientHeight)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (listRef.current && parsed.length > 0)
      listRef.current.scrollToItem(parsed.length - 1, 'end')
  }, [parsed.length])

  const Row = ({ index, style }) => {
    const item = parsed[index]
    if (!item) return null
    const isHighlight = highlightedEventId != null && item.id === highlightedEventId
    return (
      <div
        style={style}
        className={`terminal-line px-3 py-0.5 hover:bg-white/5 flex items-center gap-1.5 font-mono text-xs shrink-0 ${isHighlight ? 'terminal-line-highlight' : ''}`}
      >
        <span className="text-slate-500 tabular-nums shrink-0">[{item.time}]</span>
        <span className="text-slate-500 shrink-0">|</span>
        <span className="text-slate-300 truncate max-w-[90px]" title={item.target}>{item.target}</span>
        <span className="text-slate-500 shrink-0">|</span>
        <span className={`shrink-0 font-medium ${severityColor(item.severity)}`}>{String(item.severity).toUpperCase().slice(0, 4)}</span>
        <span className="text-slate-500 shrink-0">|</span>
        <span className="text-slate-400 truncate min-w-0 flex-1" title={item.action}>{item.action}</span>
      </div>
    )
  }

  return (
    <div className={`tactical-terminal flex flex-col h-full min-h-0 ${matrixStyle ? 'matrix-style' : ''}`}>
      <div className="terminal-header shrink-0">
        <span className="text-cyber-cyan font-semibold tracking-wider">LIVE INTEL</span>
        <span className="text-slate-500 text-xs font-mono">// {isOnline ? 'FEED.ACTIVE' : 'RECONNECTING'}</span>
      </div>
      <div ref={containerRef} className="terminal-log flex-1 min-h-0 overflow-hidden">
        {parsed.length === 0 ? (
          <div className="text-cyan-400/90 px-3 py-4 font-mono text-xs border border-cyan-500/20 rounded bg-black/20">
            {idleMessage}
            <div className="text-slate-500 mt-1 text-[10px]">{IDLE_MONITORING}</div>
          </div>
        ) : (
          <List
            ref={listRef}
            height={Math.max(200, listHeight)}
            itemCount={parsed.length}
            itemSize={ROW_HEIGHT}
            width="100%"
            className="scrollbar-thin"
          >
            {Row}
          </List>
        )}
      </div>
    </div>
  )
}
