import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import CyberLiveBackdrop from './CyberLiveBackdrop'

const here = dirname(fileURLToPath(import.meta.url))
const cssPath = resolve(here, '../styles/cyber-live-backdrop.css')
const css = readFileSync(cssPath, 'utf8')

/** Split a stylesheet into `{ selector, body }` records, ignoring `@keyframes` blocks. */
function parseRules(sheet) {
  const rules = []
  let i = 0
  while (i < sheet.length) {
    const open = sheet.indexOf('{', i)
    if (open === -1) break
    const prelude = sheet.slice(i, open).trim()
    // Walk braces so a nested block (@keyframes) is consumed whole.
    let depth = 0
    let j = open
    for (; j < sheet.length; j += 1) {
      if (sheet[j] === '{') depth += 1
      else if (sheet[j] === '}') {
        depth -= 1
        if (depth === 0) break
      }
    }
    const body = sheet.slice(open + 1, j)
    if (!prelude.startsWith('@')) rules.push({ selector: prelude, body })
    i = j + 1
  }
  return rules
}

/** `@keyframes name { … }` → `{ name: [{ stop, decls }] }`. */
function parseKeyframes(sheet) {
  const out = {}
  const re = /@keyframes\s+([\w-]+)\s*\{/g
  let match
  while ((match = re.exec(sheet)) !== null) {
    const open = sheet.indexOf('{', match.index)
    let depth = 0
    let j = open
    for (; j < sheet.length; j += 1) {
      if (sheet[j] === '{') depth += 1
      else if (sheet[j] === '}') {
        depth -= 1
        if (depth === 0) break
      }
    }
    const body = sheet.slice(open + 1, j)
    const stops = []
    const stopRe = /([\d.%a-z,\s]+?)\s*\{([^}]*)\}/g
    let stopMatch
    while ((stopMatch = stopRe.exec(body)) !== null) {
      stops.push({
        stop: stopMatch[1].trim(),
        decls: stopMatch[2].replace(/\s+/g, ' ').trim().replace(/;$/, ''),
      })
    }
    out[match[1]] = stops
    re.lastIndex = j
  }
  return out
}

const rules = parseRules(css)
const keyframes = parseKeyframes(css)

/** Every `animation:` shorthand in the sheet, paired with the rule that declares it. */
const animatedRules = rules
  .map((rule) => {
    const match = rule.body.match(/animation:\s*([\w-]+)/)
    return match ? { ...rule, keyframeName: match[1] } : null
  })
  .filter(Boolean)

function firstStop(stops) {
  return stops.find((s) => s.stop === '0%' || s.stop === 'from')
}

function lastStop(stops) {
  return stops.find((s) => s.stop === '100%' || s.stop === 'to')
}

function translate3d(decls) {
  const match = decls.match(/translate3d\(([^)]*)\)/)
  if (!match) return null
  const parts = match[1].split(',').map((p) => p.trim())
  const px = (v) => (v === '0' ? 0 : Number((v.match(/^(-?[\d.]+)px$/) || [])[1]))
  return { x: px(parts[0]), y: px(parts[1]) }
}

/** Pixel periods a tiled layer can loop on: `background-size`, or the last repeating-gradient stop. */
function tilePeriods(body) {
  const periods = new Set()
  const size = body.match(/background-size:\s*([\d.]+)px\s+([\d.]+)px/)
  if (size) {
    periods.add(Number(size[1]))
    periods.add(Number(size[2]))
  }
  for (const gradient of body.match(/repeating-linear-gradient\([^;]*\)/g) ?? []) {
    const stops = [...gradient.matchAll(/([\d.]+)px/g)].map((m) => Number(m[1]))
    if (stops.length) periods.add(Math.max(...stops))
  }
  return periods
}

afterEach(() => cleanup())

describe('CyberLiveBackdrop', () => {
  it('renders every layer declared in the stylesheet contract', () => {
    render(<CyberLiveBackdrop />)
    const root = screen.getByTestId('cyber-live-backdrop')
    expect(root).toHaveClass('wm-cyber-backdrop')
    // A class in the JSX with no rule in the CSS is an invisible layer.
    const cssClasses = new Set(
      [...css.matchAll(/\.(wm-c(?:yber|bg)[\w-]*)/g)].map((match) => match[1]),
    )
    const jsxClasses = new Set(
      [...root.querySelectorAll('[class]')].flatMap((el) => [...el.classList]),
    )
    for (const cls of jsxClasses) {
      expect(cssClasses.has(cls), `${cls} is used in JSX but has no CSS rule`).toBe(true)
    }
    expect(jsxClasses.size).toBeGreaterThanOrEqual(12)
  })

  it('is inert: decorative, non-interactive, and hidden from assistive tech', () => {
    render(<CyberLiveBackdrop className="extra-class" />)
    const root = screen.getByTestId('cyber-live-backdrop')
    expect(root).toHaveAttribute('aria-hidden', 'true')
    expect(root).toHaveClass('extra-class')
    expect(root.querySelector('canvas')).toBeNull()
    expect(root.querySelector('video')).toBeNull()
    expect(root.querySelector('img')).toBeNull()
  })

  it('animates something on every layer stack it declares', () => {
    expect(animatedRules.length).toBeGreaterThanOrEqual(8)
    for (const { keyframeName, selector } of animatedRules) {
      expect(keyframes[keyframeName], `${selector} animates undefined ${keyframeName}`).toBeTruthy()
    }
  })

  it('loops forever — every animation is declared infinite', () => {
    for (const { selector, body } of animatedRules) {
      const shorthand = body.match(/animation:\s*([^;]+);/)[1]
      expect(shorthand, `${selector} must loop forever`).toContain('infinite')
    }
  })

  /**
   * The seam test, and the reason this file exists.
   *
   * A loop is only invisible if the last frame it renders is the frame it started on. There are
   * exactly three ways a layer here is allowed to satisfy that, and every animation must be one:
   *
   *   1. it ends on the transform it started from (slow parallax drifts, opacity swells);
   *   2. it is a full 360deg rotation (the radar — same frame it began on);
   *   3. it translates a tiled background by exactly one of that layer's own pixel periods.
   *
   * Case 3 is the one that rots silently: change `background-size` from 56px to 64px and the grid
   * keeps animating, still looks fine in a screenshot, and jumps 8px once per cycle forever. This
   * asserts the translation distance against the period declared on the same rule.
   */
  it('has no visible seam: each animation closes its own loop', () => {
    for (const { selector, body, keyframeName } of animatedRules) {
      const stops = keyframes[keyframeName]
      const start = firstStop(stops)
      const end = lastStop(stops)
      expect(start, `${keyframeName} has no 0%/from stop`).toBeTruthy()
      expect(end, `${keyframeName} has no 100%/to stop`).toBeTruthy()

      // Case 1: identical endpoints.
      if (start.decls === end.decls) continue

      // Case 2: exactly one full turn.
      if (/rotate\(0deg\)/.test(start.decls) && /rotate\(360deg\)/.test(end.decls)) {
        expect(start.decls.replace('rotate(0deg)', '')).toBe(end.decls.replace('rotate(360deg)', ''))
        continue
      }

      // Case 3: one tile of travel, and nothing else about the transform may change.
      const from = translate3d(start.decls)
      const to = translate3d(end.decls)
      expect(
        from && to,
        `${keyframeName} neither returns to its start, rotates 360deg, nor translates a tile`,
      ).toBeTruthy()
      expect(from.x === 0 && from.y === 0, `${keyframeName} must start at translate3d(0,0,0)`).toBe(
        true,
      )
      expect(
        start.decls.replace(/translate3d\([^)]*\)/, ''),
        `${keyframeName} changes more than its tile offset, so the wrap is visible`,
      ).toBe(end.decls.replace(/translate3d\([^)]*\)/, ''))

      const periods = tilePeriods(body)
      expect(periods.size, `${selector} translates but declares no tile period`).toBeGreaterThan(0)
      for (const distance of [to.x, to.y].filter((v) => v !== 0)) {
        expect(
          periods.has(Math.abs(distance)),
          `${selector} travels ${distance}px per cycle but tiles at [${[...periods].join(', ')}]px — ` +
            'the loop would jump by the difference',
        ).toBe(true)
      }
      expect(to.x !== 0 || to.y !== 0, `${keyframeName} does not move`).toBe(true)
    }
  })

  it('keeps a tiled layer oversized by its period so an incoming tile is never an edge', () => {
    for (const { selector, body, keyframeName } of animatedRules) {
      const to = lastStop(keyframes[keyframeName])
      const travel = translate3d(to.decls)
      if (!travel || travel.y === 0) continue
      const offset = body.match(/top:\s*(-?[\d.]+)px/)
      expect(offset, `${selector} scrolls vertically but is not offset by its period`).toBeTruthy()
      expect(Math.abs(Number(offset[1]))).toBeGreaterThanOrEqual(Math.abs(travel.y))
      expect(body, `${selector} must be taller than the viewport by its period`).toMatch(
        /height:\s*calc\(100% \+ [\d.]+px\)/,
      )
    }
  })

  it('animates only compositor properties, so the motion cannot cost layout', () => {
    for (const { selector, keyframeName } of animatedRules) {
      for (const { stop, decls } of keyframes[keyframeName]) {
        for (const decl of decls.split(';').map((d) => d.trim()).filter(Boolean)) {
          const property = decl.split(':')[0].trim()
          expect(
            ['transform', 'opacity'].includes(property),
            `${selector} animates "${property}" at ${stop} (${keyframeName}) — only transform/opacity are composited`,
          ).toBe(true)
        }
      }
    }
  })
})
