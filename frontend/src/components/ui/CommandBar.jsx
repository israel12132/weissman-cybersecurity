import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Command as CommandIcon, CornerDownLeft, Search, Sparkles } from 'lucide-react'
import { cn } from '../../lib/cn'
import useFocusTrap from '../../hooks/useFocusTrap'

/**
 * Fuzzy score of `query` against `text` in [0,1]. Substring matches score high
 * (with a start/word-boundary bonus); otherwise an in-order subsequence match
 * scores moderately; no subsequence match scores 0.
 */
export function fuzzyScore(text, query) {
  if (!query) return 1
  const t = String(text || '').toLowerCase()
  const q = query.toLowerCase()
  if (!t) return 0
  const idx = t.indexOf(q)
  if (idx !== -1) {
    let s = 0.6 + (q.length / t.length) * 0.2
    if (idx === 0) s += 0.2
    else if (/\s|[-_/]/.test(t[idx - 1])) s += 0.1
    return Math.min(s, 1)
  }
  let ti = 0
  let qi = 0
  let hits = 0
  let contig = 0
  let maxContig = 0
  while (ti < t.length && qi < q.length) {
    if (t[ti] === q[qi]) {
      qi += 1
      hits += 1
      contig += 1
      maxContig = Math.max(maxContig, contig)
    } else {
      contig = 0
    }
    ti += 1
  }
  if (qi < q.length) return 0
  return Math.min(0.5 * (hits / q.length) + 0.1 * (maxContig / q.length), 0.55)
}

/** Best fuzzy score of a command across its title, subtitle, and keywords. */
export function scoreCommand(cmd, query) {
  if (!query) return 1
  const title = fuzzyScore(cmd.title, query)
  const subtitle = cmd.subtitle ? fuzzyScore(cmd.subtitle, query) * 0.6 : 0
  const kw = Array.isArray(cmd.keywords)
    ? Math.max(0, ...cmd.keywords.map((k) => fuzzyScore(k, query) * 0.7))
    : 0
  return Math.max(title, subtitle, kw)
}

/** Convenience open/close state for the CommandBar. */
export function useCommandBar(initial = false) {
  const [open, setOpen] = useState(initial)
  return {
    open,
    setOpen,
    openBar: useCallback(() => setOpen(true), []),
    close: useCallback(() => setOpen(false), []),
    toggle: useCallback(() => setOpen((v) => !v), []),
  }
}

/**
 * CommandBar — a reusable ⌘K command palette. Feed it a command registry; it
 * fuzzy-ranks, groups, and runs commands with full keyboard control. An optional
 * `resolveNaturalLanguage(query)` makes it AI-ready: when the typed query is a
 * sentence rather than a keyword, that async resolver (e.g. an LLM endpoint) can
 * return command-like suggestions, appended under an "AI" group.
 *
 * @param {boolean} [open] @param {(open:boolean)=>void} [onOpenChange] — controlled; omit for internal state
 * @param {boolean} [hotkey=true] — bind ⌘K / Ctrl+K to toggle
 * @param {Array<{id,title,subtitle?,group?,keywords?,icon?,shortcut?,run:Function,disabled?}>} commands
 * @param {(query:string)=>Promise<Array>} [resolveNaturalLanguage] — async NL suggestions
 * @param {string} [placeholder] @param {string} [emptyMessage] @param {number} [limit=50]
 */
export default function CommandBar({
  open: openProp,
  onOpenChange,
  hotkey = true,
  commands = [],
  resolveNaturalLanguage,
  placeholder = 'Type a command or search…',
  emptyMessage = 'No matching commands',
  limit = 50,
  className,
}) {
  const isControlled = openProp !== undefined
  const [openState, setOpenState] = useState(false)
  const open = isControlled ? openProp : openState
  const setOpen = useCallback(
    (next) => {
      const value = typeof next === 'function' ? next(open) : next
      if (!isControlled) setOpenState(value)
      onOpenChange?.(value)
    },
    [isControlled, onOpenChange, open],
  )

  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const [nlResults, setNlResults] = useState([])
  const dialogRef = useRef(null)
  const listRef = useRef(null)

  useFocusTrap(dialogRef, open)

  // ⌘K / Ctrl+K toggle + Esc close.
  useEffect(() => {
    if (!hotkey) return undefined
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setOpen((v) => !v)
      } else if (e.key === 'Escape' && open) {
        setOpen(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [hotkey, open, setOpen])

  // Lock body scroll + reset transient state when opening/closing.
  useEffect(() => {
    if (!open) {
      setQuery('')
      setNlResults([])
      setActiveIndex(0)
      return undefined
    }
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [open])

  // Debounced natural-language resolution.
  useEffect(() => {
    if (!open || !resolveNaturalLanguage) return undefined
    const q = query.trim()
    if (q.length < 3) {
      setNlResults([])
      return undefined
    }
    let cancelled = false
    const timer = setTimeout(async () => {
      try {
        const out = await resolveNaturalLanguage(q)
        if (!cancelled) setNlResults(Array.isArray(out) ? out : [])
      } catch {
        if (!cancelled) setNlResults([])
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [open, query, resolveNaturalLanguage])

  const ranked = useMemo(() => {
    const q = query.trim()
    const base = commands
      .map((cmd) => ({ cmd, score: scoreCommand(cmd, q) }))
      .filter((r) => r.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((r) => r.cmd)
    const ai = nlResults.map((c) => ({ ...c, group: c.group || 'AI', ai: true }))
    // De-dup by id, base first.
    const seen = new Set(base.map((c) => c.id))
    return [...base, ...ai.filter((c) => !seen.has(c.id))]
  }, [commands, query, nlResults, limit])

  // Group for display while keeping a flat index for keyboard nav.
  const groups = useMemo(() => {
    const map = new Map()
    ranked.forEach((cmd) => {
      const g = cmd.group || 'Commands'
      if (!map.has(g)) map.set(g, [])
      map.get(g).push(cmd)
    })
    let flat = 0
    return [...map.entries()].map(([name, items]) => ({
      name,
      items: items.map((cmd) => ({ cmd, index: flat++ })),
    }))
  }, [ranked])

  useEffect(() => {
    setActiveIndex(0)
  }, [query, ranked.length])

  const run = useCallback(
    (cmd) => {
      if (!cmd || cmd.disabled) return
      setOpen(false)
      cmd.run?.()
    },
    [setOpen],
  )

  const onInputKeyDown = useCallback(
    (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActiveIndex((i) => Math.min(i + 1, Math.max(0, ranked.length - 1)))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActiveIndex((i) => Math.max(i - 1, 0))
      } else if (e.key === 'Home') {
        e.preventDefault()
        setActiveIndex(0)
      } else if (e.key === 'End') {
        e.preventDefault()
        setActiveIndex(Math.max(0, ranked.length - 1))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        run(ranked[activeIndex])
      }
    },
    [ranked, activeIndex, run],
  )

  // Keep the active row in view.
  useEffect(() => {
    if (!open || !listRef.current) return
    const el = listRef.current.querySelector(`[data-idx="${activeIndex}"]`)
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' })
  }, [activeIndex, open])

  if (!open || typeof document === 'undefined') return null

  return createPortal(
    <div
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setOpen(false)
      }}
      className="fixed inset-0 z-modal flex items-start justify-center px-4 pt-[12vh] bg-bg-overlay backdrop-blur-sm animate-fade-in"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={placeholder}
        className={cn(
          'w-full max-w-2xl overflow-hidden rounded-2xl border border-border-strong',
          'bg-bg-elevated shadow-xl animate-slide-up',
          className,
        )}
      >
        <div className="flex items-center gap-3 border-b border-border-default p-4">
          <Search className="size-5 shrink-0 text-text-muted" aria-hidden="true" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            placeholder={placeholder}
            className="flex-1 bg-transparent text-lg text-text-primary outline-none placeholder:text-text-muted"
            autoFocus
            role="combobox"
            aria-expanded="true"
            aria-controls="commandbar-listbox"
            aria-activedescendant={ranked.length ? `cmd-opt-${activeIndex}` : undefined}
          />
          <kbd className="rounded bg-bg-3 px-2 py-1 text-xs text-text-muted">Esc</kbd>
        </div>

        <div
          ref={listRef}
          id="commandbar-listbox"
          role="listbox"
          className="max-h-[56vh] overflow-y-auto custom-scroll py-2"
        >
          {ranked.length === 0 ? (
            <div className="flex flex-col items-center gap-2 p-10 text-center text-text-muted">
              <CommandIcon className="size-7 opacity-50" aria-hidden="true" />
              <span className="text-sm">{emptyMessage}</span>
            </div>
          ) : (
            groups.map((group) => (
              <div key={group.name} className="mb-1">
                <div className="px-4 pb-1 pt-2 text-[10px] font-medium uppercase tracking-widest text-text-muted">
                  {group.name}
                </div>
                {group.items.map(({ cmd, index }) => {
                  const active = index === activeIndex
                  return (
                    <button
                      key={cmd.id ?? index}
                      type="button"
                      id={`cmd-opt-${index}`}
                      data-idx={index}
                      role="option"
                      aria-selected={active}
                      disabled={cmd.disabled}
                      onMouseEnter={() => setActiveIndex(index)}
                      onClick={() => run(cmd)}
                      className={cn(
                        'flex w-full items-center gap-3 px-4 py-2.5 text-start transition-colors',
                        active ? 'bg-accent-cyan-muted' : 'hover:bg-bg-2',
                        cmd.disabled && 'opacity-40',
                      )}
                    >
                      <span className="inline-flex size-5 shrink-0 items-center justify-center text-text-tertiary [&>svg]:size-4">
                        {cmd.ai ? <Sparkles className="text-accent-violet" aria-hidden="true" /> : cmd.icon}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-text-primary">{cmd.title}</span>
                        {cmd.subtitle && (
                          <span className="block truncate text-xs text-text-muted">{cmd.subtitle}</span>
                        )}
                      </span>
                      {cmd.shortcut && (
                        <kbd className="shrink-0 rounded bg-bg-3 px-1.5 py-0.5 text-[10px] text-text-muted">
                          {cmd.shortcut}
                        </kbd>
                      )}
                      {active && <CornerDownLeft className="size-4 shrink-0 text-accent-cyan" aria-hidden="true" />}
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

export { CommandBar }
