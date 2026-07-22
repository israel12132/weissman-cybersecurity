import { useEffect, useRef, useState } from 'react'
import { CornerDownLeft, Play, Sparkles } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * AiCommandConsole — a conversational, context-aware command surface ("Ask
 * Weissman"). It renders a multi-turn thread where assistant turns can carry
 * one-click actions (run a playbook, launch a scan, open a view), a context
 * chip row that grounds the model, and suggested next prompts. Presentational:
 * wire `onSubmit` to your LLM endpoint and append the returned turn to `messages`.
 *
 * @param {Array<{id?:string|number,role:'user'|'assistant',content:React.ReactNode,
 *   actions?:Array<{id?:string,label:React.ReactNode,intent?:'primary'|'danger'}>}>} messages
 * @param {(text:string)=>void} onSubmit
 * @param {(action:object,message:object)=>void} [onRunAction]
 * @param {Array<{id?:string,label:string,prompt?:string}>} [suggestions]
 * @param {Array<{id?:string,label:React.ReactNode}>} [context] — grounding chips
 * @param {boolean} [busy=false] — assistant is thinking
 * @param {string} [placeholder]
 */
export default function AiCommandConsole({
  messages = [],
  onSubmit,
  onRunAction,
  suggestions = [],
  context = [],
  busy = false,
  placeholder = 'Ask or command — e.g. “run ransomware playbook on Acme prod”',
  className,
  ...props
}) {
  const [value, setValue] = useState('')
  const threadRef = useRef(null)

  // Keep the newest turn in view.
  useEffect(() => {
    const el = threadRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages.length, busy])

  const submit = (text) => {
    const t = (text ?? value).trim()
    if (!t || busy) return
    onSubmit?.(t)
    setValue('')
  }

  return (
    <div
      className={cn(
        'flex flex-col overflow-hidden rounded-2xl border border-border-strong bg-bg-2',
        className,
      )}
      {...props}
    >
      {/* Header + context chips */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border-default px-4 py-2.5">
        <span className="inline-flex size-6 items-center justify-center rounded-md bg-accent-violet-muted text-accent-violet">
          <Sparkles className="size-3.5" aria-hidden="true" />
        </span>
        <span className="text-sm font-semibold text-text-primary">Ask Weissman</span>
        {context.length > 0 && (
          <span className="ms-auto flex flex-wrap items-center gap-1.5">
            {context.map((c, i) => (
              <span
                key={c.id ?? i}
                className="inline-flex items-center rounded-full border border-border-default bg-bg-3 px-2 py-0.5 text-[10px] text-text-tertiary"
              >
                {c.label}
              </span>
            ))}
          </span>
        )}
      </div>

      {/* Conversation thread */}
      <div
        ref={threadRef}
        role="log"
        aria-live="polite"
        aria-label="Conversation"
        className="flex max-h-80 min-h-[8rem] flex-col gap-3 overflow-y-auto custom-scroll p-4"
      >
        {messages.length === 0 && !busy && (
          <p className="m-auto max-w-sm text-center text-xs text-text-muted">
            Ask a question or issue a command in natural language. I can run scans,
            launch playbooks, and pull up findings.
          </p>
        )}
        {messages.map((m, i) => {
          const isUser = m.role === 'user'
          return (
            <div key={m.id ?? i} className={cn('flex', isUser ? 'justify-end' : 'justify-start')}>
              <div
                className={cn(
                  'max-w-[85%] rounded-2xl px-3.5 py-2 text-sm leading-relaxed',
                  isUser
                    ? 'bg-accent-cyan-muted text-text-primary'
                    : 'bg-bg-3 text-text-secondary',
                )}
              >
                <div>{m.content}</div>
                {!isUser && Array.isArray(m.actions) && m.actions.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {m.actions.map((a, ai) => (
                      <button
                        key={a.id ?? ai}
                        type="button"
                        onClick={() => onRunAction?.(a, m)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium',
                          'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
                          a.intent === 'danger'
                            ? 'border-severity-critical-border bg-severity-critical-bg text-severity-critical'
                            : 'border-accent-cyan/40 bg-accent-cyan-muted text-accent-cyan',
                        )}
                      >
                        <Play className="size-3" aria-hidden="true" />
                        {a.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )
        })}
        {busy && (
          <div className="flex justify-start">
            <div className="inline-flex items-center gap-1 rounded-2xl bg-bg-3 px-3.5 py-2.5" aria-label="Assistant is thinking">
              <span className="size-1.5 animate-pulse-subtle rounded-full bg-text-muted" />
              <span className="size-1.5 animate-pulse-subtle rounded-full bg-text-muted" style={{ animationDelay: '150ms' }} />
              <span className="size-1.5 animate-pulse-subtle rounded-full bg-text-muted" style={{ animationDelay: '300ms' }} />
            </div>
          </div>
        )}
      </div>

      {/* Suggestions */}
      {suggestions.length > 0 && (
        <div className="flex flex-wrap gap-1.5 border-t border-border-subtle px-4 py-2">
          {suggestions.map((s, i) => (
            <button
              key={s.id ?? i}
              type="button"
              onClick={() => submit(s.prompt ?? s.label)}
              className="rounded-full border border-border-default bg-bg-3 px-2.5 py-1 text-[11px] text-text-tertiary hover:border-border-strong hover:text-text-secondary focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
            >
              {s.label}
            </button>
          ))}
        </div>
      )}

      {/* Composer */}
      <form
        className="flex items-center gap-2 border-t border-border-default p-3"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          aria-label="Ask Weissman"
          className="flex-1 rounded-lg border border-border-default bg-bg-1 px-3 py-2 text-sm text-text-primary outline-none placeholder:text-text-muted focus-visible:border-accent-cyan/50 focus-visible:shadow-[var(--focus-ring)]"
        />
        <button
          type="submit"
          disabled={busy || !value.trim()}
          aria-label="Send"
          className="inline-flex size-9 items-center justify-center rounded-lg bg-accent-gradient text-text-inverse disabled:opacity-40 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
        >
          <CornerDownLeft className="size-4" aria-hidden="true" />
        </button>
      </form>
    </div>
  )
}

export { AiCommandConsole }
