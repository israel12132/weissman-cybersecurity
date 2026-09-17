import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ZeroDayRadar.jsx'),
  'utf8',
)

describe('ZeroDayRadar live-only truth', () => {
  it('does not paint leftover leftover-feed after a failed threat-intel GET', () => {
    expect(src).toMatch(/\{!feedError && feedItems\.map\(\(item, i\) => \(/)
    expect(src).toMatch(/data-testid="zero-day-feed-unavailable"/)
    expect(src).toMatch(/setFeedError\(e\?\.message \|\| t\(`\$\{NS\}\.feed_unavailable`\)\)/)
    expect(src).not.toMatch(/setFeedItems\(\[\]\)/)
  })
})
