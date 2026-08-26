import { AttackTheater } from './AttackTheater'
import { CommandCenterMock } from './CommandCenterMock'
import { ProductVisual } from './ProductVisual'

const accents: Record<string, string> = {
  accent: 'var(--accent)',
  risk: 'var(--risk)',
  ops: 'var(--ops)',
}

export function ProductScene({
  productId,
  accent = 'accent',
}: {
  productId?: string
  accent?: string
}) {
  if (productId === 'attack-path-intelligence') return <AttackTheater />
  if (productId === 'security-operations' || productId === 'detection-response') return <CommandCenterMock />
  return <ProductVisual accent={accents[accent] ?? accent} />
}
