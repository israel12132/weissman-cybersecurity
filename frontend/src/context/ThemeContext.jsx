import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'

const ThemeContext = createContext(null)

const STORAGE_KEY = 'weissman_theme'
const THEMES = ['dark', 'light']

/** Resolve the initial theme: stored pref → OS preference → dark. */
function initialTheme() {
  if (typeof window === 'undefined') return 'dark'
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && THEMES.includes(stored)) return stored
  } catch {
    /* ignore storage errors */
  }
  try {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      return 'light'
    }
  } catch {
    /* ignore */
  }
  return 'dark'
}

function applyTheme(theme) {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-theme', theme)
  document.documentElement.style.colorScheme = theme
}

/**
 * App theme provider. Dark is the default; light is opt-in and applied by
 * stamping `data-theme` on <html>, which flips the CSS-variable token layer.
 * Persisted per-browser (theme preference is not sensitive).
 */
export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(initialTheme)

  useEffect(() => {
    applyTheme(theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const setTheme = useCallback((next) => {
    setThemeState(THEMES.includes(next) ? next : 'dark')
  }, [])

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }, [])

  const value = { theme, setTheme, toggleTheme, isLight: theme === 'light' }
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) {
    // Safe fallback outside the provider (tests, isolated renders).
    return { theme: 'dark', setTheme: () => {}, toggleTheme: () => {}, isLight: false }
  }
  return ctx
}
