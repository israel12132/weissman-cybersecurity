import { useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, RefreshCw, ListChecks } from 'lucide-react'
import useTenantDirectory from '../../hooks/useTenantDirectory'
import { AUTH_OPTION_STYLE, FloatingInput, FloatingSelect } from './AuthFields'
import Button from '../ui/Button'

/**
 * Tenant slug control for the sign-in form: a live workspace picker, not a free-text box.
 *
 * `api_login` resolves the slug *before* it checks the password and answers an unknown slug with the
 * same "Invalid email or password" as a bad credential — so as free text this field turned a typo
 * into an unexplainable rejection, and it required knowing a string that is nowhere in the UI. The
 * options now come from `GET /api/auth/tenant-directory`.
 *
 * The select is not the only path, because the server does not always list: multi-tenant production
 * instances withhold the slug list (it is a customer list) unless the operator opts in, and the API
 * can be down. In those cases — and via an explicit "other workspace" option when the list may be
 * incomplete — the field falls back to manual entry with the reason stated, so nobody is ever locked
 * out of a workspace the picker does not know about.
 */

/** Sentinel option value; not a legal slug (`cleanSlug` rejects underscores), so it cannot collide. */
const CUSTOM_OPTION = '__custom__'

export default function TenantSlugField({
  id = 'tenant',
  value,
  onChange,
  disabled = false,
  className = '',
}) {
  const { t } = useTranslation()
  const { status, tenants, defaultSlug, allowCustom, reload } = useTenantDirectory()
  const [manual, setManual] = useState(false)
  const hintId = useId()
  const manualInputRef = useRef(null)
  const adoptedRef = useRef(false)
  const focusManualRef = useRef(false)

  // Adopt a slug that actually exists, once, as soon as the directory arrives. Without this the form
  // would keep submitting its built-in default on an instance whose workspace is named anything else.
  useEffect(() => {
    if (status !== 'ready' || adoptedRef.current || tenants.length === 0) return
    adoptedRef.current = true
    if (tenants.some((tenant) => tenant.slug === value)) return
    const preferred = tenants.find((tenant) => tenant.slug === defaultSlug) ?? tenants[0]
    onChange(preferred.slug)
  }, [status, tenants, defaultSlug, value, onChange])

  useEffect(() => {
    if (focusManualRef.current && manualInputRef.current) {
      focusManualRef.current = false
      manualInputRef.current.focus()
    }
  }, [manual])

  const label = t('auth.tenant_slug')
  const listAvailable = status === 'ready' && tenants.length > 0
  const showManual = manual || (!listAvailable && status !== 'loading')

  if (showManual) {
    const hint =
      status === 'error'
        ? t('auth.tenant_directory_unavailable')
        : status === 'restricted'
          ? t('auth.tenant_directory_restricted')
          : t('auth.tenant_manual_hint')
    return (
      <div className={className}>
        <FloatingInput
          id={id}
          ref={manualInputRef}
          label={label}
          type="text"
          autoComplete="organization"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          describedBy={hintId}
        />
        <div id={hintId} className="mt-2 flex items-center gap-2 px-1 text-[11px] text-white/40">
          <span className="flex-1">{hint}</span>
          {listAvailable ? (
            <Button
              variant="unstyled"
              type="button"
              onClick={() => setManual(false)}
              className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-cyan-400/80 transition-colors hover:bg-cyan-400/10 hover:text-cyan-300"
            >
              <ListChecks className="h-3 w-3" aria-hidden />
              {t('auth.tenant_back_to_list')}
            </Button>
          ) : (
            status === 'error' && (
              <Button
                variant="unstyled"
                type="button"
                onClick={reload}
                className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-cyan-400/80 transition-colors hover:bg-cyan-400/10 hover:text-cyan-300"
              >
                <RefreshCw className="h-3 w-3" aria-hidden />
                {t('auth.tenant_retry')}
              </Button>
            )
          )}
        </div>
      </div>
    )
  }

  const loading = status === 'loading'
  const selectValue = loading
    ? value
    : tenants.some((tenant) => tenant.slug === value)
      ? value
      : (tenants.find((tenant) => tenant.slug === defaultSlug)?.slug ?? tenants[0]?.slug ?? value)

  return (
    <div className={className}>
      <FloatingSelect
        id={id}
        label={label}
        value={selectValue}
        disabled={disabled || loading}
        describedBy={hintId}
        onChange={(e) => {
          if (e.target.value === CUSTOM_OPTION) {
            focusManualRef.current = true
            setManual(true)
            return
          }
          onChange(e.target.value)
        }}
        endAdornment={
          loading ? (
            <Loader2
              className="pointer-events-none absolute end-4 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-cyan-400/70"
              aria-hidden
            />
          ) : undefined
        }
      >
        {loading ? (
          <option value={selectValue} style={AUTH_OPTION_STYLE}>
            {t('auth.tenant_loading')}
          </option>
        ) : (
          <>
            {tenants.map((tenant) => (
              <option key={tenant.slug} value={tenant.slug} style={AUTH_OPTION_STYLE}>
                {tenant.name === tenant.slug ? tenant.slug : `${tenant.name} · ${tenant.slug}`}
              </option>
            ))}
            {allowCustom && (
              <option value={CUSTOM_OPTION} style={AUTH_OPTION_STYLE}>
                {t('auth.tenant_option_custom')}
              </option>
            )}
          </>
        )}
      </FloatingSelect>
      <p id={hintId} className="mt-2 px-1 text-[11px] text-white/35">
        {loading ? t('auth.tenant_loading') : t('auth.tenant_select_hint')}
      </p>
    </div>
  )
}
