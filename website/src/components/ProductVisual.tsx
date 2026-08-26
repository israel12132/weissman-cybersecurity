/** Original product composition — attack path + severity rail. Not a vendor screenshot. */
export function ProductVisual({ accent = 'var(--accent)' }: { accent?: string }) {
  return (
    <figure className="surface relative overflow-hidden p-4 shadow-[var(--shadow)]" aria-label="Illustrative attack-path composition">
      <figcaption className="mb-3 flex items-center justify-between text-[0.7rem] uppercase tracking-[0.14em] text-dim">
        <span>Attack path · illustrative</span>
        <span className="text-ops">probe live</span>
      </figcaption>
      <svg viewBox="0 0 560 320" className="h-auto w-full" role="img" aria-label="Internet edge connecting through a choke-point to a crown jewel">
        <defs>
          <linearGradient id="pv-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor={accent} stopOpacity="0.2" />
            <stop offset="1" stopColor={accent} />
          </linearGradient>
        </defs>
        <rect width="560" height="320" fill="#0a0e14" rx="10" />
        <path d="M70 80 H210 Q250 80 250 120 V200 Q250 240 290 240 H470" stroke="url(#pv-line)" strokeWidth="2" fill="none" />
        <path d="M70 200 H180 Q220 200 220 160" stroke={accent} strokeOpacity="0.35" strokeWidth="1.5" fill="none" />
        <Node x={70} y={80} label="edge-web" tone="#22d3ee" />
        <Node x={70} y={200} label="vpn-gw" tone="#e8b86d" />
        <Node x={250} y={160} label="idp-core" tone="#22d3ee" />
        <Node x={470} y={240} label="crown-db" tone="#f07167" />
        <text x="24" y="300" fill="#7d776c" fontSize="11" fontFamily="JetBrains Mono, monospace">
          internet_exposed → choke_point → crown_jewel
        </text>
      </svg>
    </figure>
  )
}

function Node({ x, y, label, tone }: { x: number; y: number; label: string; tone: string }) {
  return (
    <g>
      <circle cx={x} cy={y} r="9" fill="#10141b" stroke={tone} strokeWidth="2" />
      <text x={x + 16} y={y + 4} fill="#f4efe6" fontSize="12" fontFamily="Inter, sans-serif">
        {label}
      </text>
    </g>
  )
}
