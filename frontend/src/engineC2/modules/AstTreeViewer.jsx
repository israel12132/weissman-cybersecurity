import { memo, useCallback, useEffect, useMemo, useState } from 'react'
import { FixedSizeList as List } from 'react-window'
import CopyButton from '../../components/ui/CopyButton'
import { capAstMutations, prefetchAstCapWasm } from '../astCapWasm'

const ROW_HEIGHT = 36
const VIEWPORT_ROWS = 14
const MAX_BYTES_ESTIMATE = 50 * 1024 * 1024

function AstRow({ index, style, data }) {
  const { items } = data
  const text = items[index] ?? ''
  return (
    <div
      style={style}
      className="flex items-start gap-2 px-3 border-b border-white/5 hover:bg-white/[0.02]"
    >
      <span className="shrink-0 text-[10px] font-mono text-white/20 tabular-nums pt-1 w-10 text-right">
        {index + 1}
      </span>
      <code className="flex-1 min-w-0 text-[11px] font-mono text-white/70 break-all pt-0.5 ltr-only">
        {text}
      </code>
      <span className="shrink-0 pt-0.5 opacity-60 hover:opacity-100">
        <CopyButton value={text} size="sm" />
      </span>
    </div>
  )
}

const MemoAstRow = memo(AstRow)

export default function AstTreeViewer({
  nodes = [],
  maxNodes = 50_000,
  loading = false,
  emptyTitle = 'AST mutations',
  emptyBody = 'Run preview to populate the mutation tree.',
  className = '',
}) {
  const [capped, setCapped] = useState([])
  const rawCount = Array.isArray(nodes) ? nodes.length : 0

  useEffect(() => {
    prefetchAstCapWasm()
  }, [])

  useEffect(() => {
    let cancelled = false
    const list = Array.isArray(nodes) ? nodes.map(String) : []
    const byteEst = list.reduce((n, s) => n + s.length, 0)
    const budget = byteEst > MAX_BYTES_ESTIMATE
      ? Math.min(maxNodes, 5_000)
      : maxNodes

    capAstMutations(list, budget, MAX_BYTES_ESTIMATE).then((result) => {
      if (!cancelled) setCapped(result)
    })
    return () => {
      cancelled = true
    }
  }, [nodes, maxNodes])

  const height = Math.min(VIEWPORT_ROWS, Math.max(4, capped.length)) * ROW_HEIGHT

  const itemData = useMemo(
    () => ({ items: capped }),
    [capped],
  )

  const onCopy = useCallback(() => {}, [])

  if (loading && !capped.length) {
    return (
      <div className={`rounded-xl border border-white/10 bg-black/40 p-6 ${className}`}>
        <div className="animate-pulse space-y-2">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-3 bg-white/5 rounded w-full" />
          ))}
        </div>
      </div>
    )
  }

  if (!capped.length) {
    return (
      <div className={`rounded-xl border border-white/10 bg-black/40 p-6 text-center ${className}`}>
        <p className="text-sm font-medium text-white/50">{emptyTitle}</p>
        <p className="text-[11px] text-white/30 mt-1">{emptyBody}</p>
      </div>
    )
  }

  return (
    <div className={`rounded-xl border border-amber-500/20 bg-black/40 overflow-hidden ${className}`}>
      <div className="px-3 py-2 border-b border-white/10 flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-widest text-amber-200/70">
          AST tree · {capped.length.toLocaleString()} nodes
        </span>
        {capped.length < rawCount && (
          <span className="text-[9px] font-mono text-rose-300/80">
            truncated for safety
          </span>
        )}
      </div>
      <List
        height={height}
        itemCount={capped.length}
        itemSize={ROW_HEIGHT}
        width="100%"
        itemData={{ ...itemData, onCopy }}
        overscanCount={8}
      >
        {MemoAstRow}
      </List>
    </div>
  )
}
