import { useEffect, useRef } from 'react'

export default function AttackLifecycleTicker({ events }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current && events?.length)
      scrollRef.current.scrollLeft = scrollRef.current.scrollWidth
  }, [events])

  if (!events?.length) {
    return (
      <div className="flex-shrink-0 h-10 border-t border-war-border bg-war-dark flex items-center px-4">
        <span className="text-war-silver/50 text-xs font-mono">Attack Lifecycle Ticker — Waiting for activity...</span>
      </div>
    )
  }

  return (
    <div className="flex-shrink-0 h-10 border-t border-war-border bg-war-dark overflow-hidden">
      <div
        ref={scrollRef}
        className="ticker-wrap h-full flex items-center gap-6 px-4 overflow-x-auto overflow-y-hidden scroll-smooth"
        style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
      >
        {events.map((e, i) => (
          <div
            key={i}
            className="flex-shrink-0 flex items-center gap-3 text-xs font-mono py-1"
          >
            <span className="text-war-cyan/90 tabular-nums">{e.time}</span>
            <span className="text-war-silver/50">|</span>
            <span className="text-war-gold/90 truncate max-w-[120px]" title={e.target}>
              {e.target || '—'}
            </span>
            <span className="text-war-silver/50">|</span>
            <span className="text-war-silver/70 truncate max-w-[100px]" title={e.agentId}>
              {e.agentId}
            </span>
            <span className="text-war-silver/50">|</span>
            <span className="text-war-silver">{e.message}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
