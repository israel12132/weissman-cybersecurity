const COLS = 4
const ROWS = 3
const TOTAL = COLS * ROWS

export default function AssetHexGrid() {
  return (
    <div className="asset-hex-grid">
      <div className="text-cyber-cyan font-semibold text-xs tracking-widest mb-2 uppercase">
        Asset Grid
      </div>
      <div
        className="grid gap-1.5 justify-items-center"
        style={{ gridTemplateColumns: `repeat(${COLS}, 1fr)` }}
      >
        {Array.from({ length: TOTAL }, (_, i) => (
          <div
            key={i}
            className="hex-cell w-8 h-9 flex items-center justify-center rounded-sm border border-cyber-cyan/30 bg-cyber-cyan/5 text-cyber-cyan/80 font-mono text-[10px] transition-all duration-500"
            style={{ animation: 'hex-pulse 2.5s ease-in-out infinite' }}
          >
            {String(i + 1).padStart(2, '0')}
          </div>
        ))}
      </div>
    </div>
  )
}
