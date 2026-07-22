import { useId } from 'react'
import { RotateCcw } from 'lucide-react'
import { cn } from '../../lib/cn'
import Button from './Button.jsx'
import Input from './Input.jsx'
import Badge from './Badge.jsx'

const DEFAULTS = {
  primary: '#22d3ee',
  secondary: '#8b5cf6',
  gradientMid: '#6366f1',
}

const COLOR_FIELDS = [
  { key: 'primary', label: 'Primary' },
  { key: 'gradientMid', label: 'Gradient mid' },
  { key: 'secondary', label: 'Secondary' },
]

/**
 * WhiteLabelStudio — a controlled tenant-branding editor that drives the
 * runtime white-label engine (the `--brand-*` seeds in tokens.css). Pure and
 * presentational: it reports edits via `onChange(partialBrand)`; wire that to
 * `useTheme().setBrand` to apply live, and `onReset` to `clearBrand`.
 *
 * @param {{name?:string,logoUrl?:string,primary?:string,secondary?:string,gradientMid?:string}|null} brand
 * @param {(partial:object)=>void} onChange
 * @param {()=>void} [onReset]
 */
export default function WhiteLabelStudio({ brand, onChange, onReset, className, ...props }) {
  const uid = useId()
  const b = brand || {}
  const emit = (key, value) => onChange?.({ [key]: value })

  return (
    <div
      className={cn('grid gap-4 sm:grid-cols-2', className)}
      {...props}
    >
      {/* Editor */}
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-3">
          <Input
            label="Brand name"
            value={b.name ?? ''}
            onChange={(e) => emit('name', e.target.value)}
            placeholder="Acme Security"
          />
          <Input
            label="Logo URL"
            value={b.logoUrl ?? ''}
            onChange={(e) => emit('logoUrl', e.target.value)}
            placeholder="https://…/logo.svg"
          />
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium text-text-secondary">Palette</span>
          <div className="flex flex-wrap gap-4">
            {COLOR_FIELDS.map(({ key, label }) => (
              <label key={key} htmlFor={`${uid}-${key}`} className="flex items-center gap-2 text-xs text-text-secondary">
                <input
                  id={`${uid}-${key}`}
                  type="color"
                  aria-label={`${label} color`}
                  value={b[key] ?? DEFAULTS[key]}
                  onChange={(e) => emit(key, e.target.value)}
                  className="size-8 cursor-pointer rounded-md border border-border-default bg-transparent"
                />
                {label}
              </label>
            ))}
          </div>
        </div>

        {onReset && (
          <div>
            <Button variant="ghost" size="sm" leftIcon={<RotateCcw />} onClick={onReset} disabled={!brand}>
              Reset to default palette
            </Button>
          </div>
        )}
      </div>

      {/* Live preview — reflects the applied brand when onChange drives setBrand. */}
      <div className="flex flex-col gap-3 rounded-xl border border-border-default bg-bg-2 p-4">
        <span className="text-[10px] uppercase tracking-widest text-text-muted">Preview</span>
        <div className="flex items-center gap-3">
          {b.logoUrl ? (
            <img src={b.logoUrl} alt="" className="size-8 rounded-md object-contain" />
          ) : (
            <span className="inline-flex size-8 items-center justify-center rounded-md bg-accent-gradient text-text-inverse text-xs font-bold">
              {(b.name || 'W').slice(0, 1).toUpperCase()}
            </span>
          )}
          <span className="font-display text-sm font-semibold text-text-primary">
            {b.name || 'Weissman'}
          </span>
        </div>
        <div className="h-8 rounded-lg bg-accent-gradient" aria-hidden="true" />
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm">Primary action</Button>
          <Button size="sm" variant="premium">Premium</Button>
          <Badge kind="severity" value="critical" />
        </div>
      </div>
    </div>
  )
}

export { WhiteLabelStudio, DEFAULTS as WHITE_LABEL_DEFAULTS }
