/**
 * Class-name merge helper (design-system primitive) — a dependency-free,
 * self-contained port of `clsx`.
 *
 * Why inline instead of `import clsx from 'clsx'`: this module is imported by
 * the shared UI primitives (Button, Card, Input, …), so bundlers place it in
 * the app's shared-UI chunk alongside React components. When it also imported
 * the `clsx` package, that single `clsx` module became shared between this
 * React-bearing chunk AND pure vendor libraries (recharts, @xyflow) that use
 * `clsx` too. The bundler could only put `clsx` in one chunk, so it landed in
 * the React-bearing shared-UI chunk — and the vendor chunks then imported that
 * chunk back, forming a chunk cycle (vendor-react → vendor-xyflow →
 * vendor-recharts → shared-UI → vendor-react). That cycle made a dependent
 * chunk dereference `React.forwardRef` before React had initialized, throwing
 * "Cannot read properties of undefined (reading 'forwardRef')" and leaving the
 * production SPA unmounted (<div id="root"> empty).
 *
 * Keeping this helper free of the shared `clsx` module means `clsx` is now used
 * only by the vendor libraries, so it lands in a pure vendor chunk and the
 * cross-chunk cycle is gone — the source graph is a clean DAG and Rollup's
 * automatic ordering keeps React initialized before every consumer.
 *
 * Behaviour is identical to `clsx`: strings/numbers are kept, falsy values are
 * dropped, arrays are flattened recursively, and object keys with truthy values
 * are emitted.
 */

function toVal(mix) {
  let str = ''
  if (typeof mix === 'string' || typeof mix === 'number') {
    str += mix
  } else if (typeof mix === 'object' && mix !== null) {
    if (Array.isArray(mix)) {
      for (let i = 0; i < mix.length; i += 1) {
        if (mix[i]) {
          const inner = toVal(mix[i])
          if (inner) {
            if (str) str += ' '
            str += inner
          }
        }
      }
    } else {
      for (const key in mix) {
        if (mix[key]) {
          if (str) str += ' '
          str += key
        }
      }
    }
  }
  return str
}

/** Merge class names — accepts strings, numbers, arrays, and objects. */
export function cn(...inputs) {
  let str = ''
  for (let i = 0; i < inputs.length; i += 1) {
    const arg = inputs[i]
    if (arg) {
      const val = toVal(arg)
      if (val) {
        if (str) str += ' '
        str += val
      }
    }
  }
  return str
}

export default cn
