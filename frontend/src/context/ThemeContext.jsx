import { createContext, useContext, useState, useCallback, useEffect } from 'react'

const ThemeContext = createContext(null)

const STORAGE_KEY = 'weissman_theme'
const BRAND_STORAGE_KEY = 'weissman_brand'
const THEMES = ['dark', 'light', 'high-contrast']

/* White-label brand seeds — mirror the --brand-* variables in tokens.css. Any
   subset can be overridden per tenant; the rest fall back to the token defaults. */
const BRAND_VARS = {
  primary: '--brand-primary',
  primarySoft: '--brand-primary-soft',
  secondary: '--brand-secondary',
  secondarySoft: '--brand-secondary-soft',
  gradientMid: '--brand-gradient-mid',
}

/**
 * Resolve the initial theme: explicit stored pref → dark.
 *
 * Dark is the fully-polished, production default. We intentionally do NOT
 * auto-adopt the OS `prefers-color-scheme: light` yet: light mode is an explicit
 * opt-in (via the toggle) while its gradient/bespoke surfaces are still being
 * polished, so no customer is shown an unfinished light theme by accident.
 * High-contrast is likewise opt-in (accessibility toggle / cycle).
 */
function initialTheme() {
  if (typeof window === 'undefined') return 'dark'
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && THEMES.includes(stored)) return stored
  } catch {
    /* ignore storage errors */
  }
  return 'dark'
}

function initialBrand() {
  if (typeof window === 'undefined') return null
  try {
    const raw = localStorage.getItem(BRAND_STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') return parsed
    }
  } catch {
    /* ignore storage / parse errors */
  }
  return null
}

function applyTheme(theme) {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-theme', theme)
  // High-contrast is a dark-based theme, so native form controls stay dark.
  document.documentElement.style.colorScheme = theme === 'light' ? 'light' : 'dark'
}

/**
 * Stamp (or clear) the white-label brand seeds as inline CSS variables on
 * <html>. Inline vars win over the :root defaults in tokens.css, so the entire
 * derived accent system (fills, gradients, glows, borders, focus ring,
 * selection) re-tints without touching any component. Passing null clears every
 * override and reverts to the default cyan→violet palette.
 */
function applyBrand(brand) {
  if (typeof document === 'undefined') return
  const style = document.documentElement.style
  for (const [key, cssVar] of Object.entries(BRAND_VARS)) {
    const value = brand?.[key]
    if (value) style.setProperty(cssVar, value)
    else style.removeProperty(cssVar)
  }
}

/**
 * App theme provider. Dark is the default; light and high-contrast are opt-in,
 * applied by stamping `data-theme` on <html> (which flips the CSS-variable token
 * layer). Also owns runtime white-label branding: `setBrand({ primary, ... })`
 * re-tints the accent system per tenant, and exposes `logoUrl` / `brandName` for
 * chrome to consume. Both theme and brand are persisted per-browser.
 */
export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(initialTheme)
  const [brand, setBrandState] = useState(initialBrand)

  useEffect(() => {
    applyTheme(theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  useEffect(() => {
    applyBrand(brand)
    try {
      if (brand) localStorage.setItem(BRAND_STORAGE_KEY, JSON.stringify(brand))
      else localStorage.removeItem(BRAND_STORAGE_KEY)
    } catch {
      /* ignore */
    }
  }, [brand])

  const setTheme = useCallback((next) => {
    setThemeState(THEMES.includes(next) ? next : 'dark')
  }, [])

  // Backward-compatible 2-way toggle (dark ⇄ light) for existing callers.
  const toggleTheme = useCallback(() => {
    setThemeState((prev) => (prev === 'light' ? 'dark' : 'light'))
  }, [])

  // 3-way cycle for the accessibility control: dark → light → high-contrast → dark.
  const cycleTheme = useCallback(() => {
    setThemeState((prev) => {
      const i = THEMES.indexOf(prev)
      return THEMES[(i + 1) % THEMES.length]
    })
  }, [])

  // Merge a partial brand override (null resets to defaults).
  const setBrand = useCallback((next) => {
    setBrandState((prev) => (next ? { ...(prev || {}), ...next } : null))
  }, [])

  const clearBrand = useCallback(() => setBrandState(null), [])

  const value = {
    theme,
    setTheme,
    toggleTheme,
    cycleTheme,
    themes: THEMES,
    isLight: theme === 'light',
    isDark: theme === 'dark',
    isHighContrast: theme === 'high-contrast',
    brand,
    setBrand,
    clearBrand,
    logoUrl: brand?.logoUrl || null,
    brandName: brand?.name || null,
  }
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) {
    // Safe fallback outside the provider (tests, isolated renders).
    return {
      theme: 'dark',
      setTheme: () => {},
      toggleTheme: () => {},
      cycleTheme: () => {},
      themes: THEMES,
      isLight: false,
      isDark: true,
      isHighContrast: false,
      brand: null,
      setBrand: () => {},
      clearBrand: () => {},
      logoUrl: null,
      brandName: null,
    }
  }
  return ctx
}
