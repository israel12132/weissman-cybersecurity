import React from 'react'

/**
 * Brand wordmark. `compact` shows just the shield icon (for narrow sidebars),
 * `size` is height in px (width auto-scales).
 */
export default function Logo({ compact = false, size = 32, className = '' }) {
  const ratio = compact ? 1 : 240 / 64
  const w = Math.round(size * ratio)
  const ariaLabel = compact ? 'Weissman' : 'Weissman Cybersecurity'
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={compact ? '0 0 64 64' : '0 0 240 64'}
      width={w}
      height={size}
      fill="none"
      role="img"
      aria-label={ariaLabel}
      className={className}
    >
      <defs>
        <linearGradient id={`wg-${compact ? 'c' : 'f'}`} x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#0ea5e9" />
        </linearGradient>
        {!compact && (
          <linearGradient id="wt" x1="80" y1="0" x2="240" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#e2e8f0" />
            <stop offset="1" stopColor="#94a3b8" />
          </linearGradient>
        )}
      </defs>
      <path
        d={compact
          ? 'M32 4 L58 12 V32 C58 48 32 60 32 60 C32 60 6 48 6 32 V12 Z'
          : 'M32 6 L56 14 V32 C56 46 32 58 32 58 C32 58 8 46 8 32 V14 Z'}
        fill={`url(#wg-${compact ? 'c' : 'f'})`}
        stroke="#0e7490"
        strokeWidth="1.5"
      />
      <path
        d={compact
          ? 'M16 28 L25 42 L34 22 L43 42 L52 24'
          : 'M18 28 L26 40 L34 22 L42 40 L50 24'}
        stroke="#020617"
        strokeWidth={compact ? 4 : 3}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      {!compact && (
        <>
          <text
            x="78"
            y="36"
            fontFamily="'Orbitron','Rajdhani',ui-sans-serif,system-ui,sans-serif"
            fontWeight="700"
            fontSize="22"
            letterSpacing="2.5"
            fill="url(#wt)"
          >
            WEISSMAN
          </text>
          <text
            x="78"
            y="52"
            fontFamily="'JetBrains Mono',ui-monospace,monospace"
            fontSize="10"
            letterSpacing="3"
            fill="#22d3ee"
            opacity="0.85"
          >
            CYBERSECURITY
          </text>
        </>
      )}
    </svg>
  )
}
