import { describe, it, expect } from 'vitest'
import { normalizeRiskGraph, severityFromRisk } from './RiskGraphVisualization.jsx'

describe('severityFromRisk', () => {
  it('bands 0–100 into cockpit severities', () => {
    expect(severityFromRisk(0)).toBe('low')
    expect(severityFromRisk(29)).toBe('low')
    expect(severityFromRisk(30)).toBe('medium')
    expect(severityFromRisk(60)).toBe('high')
    expect(severityFromRisk(80)).toBe('critical')
  })
})

describe('normalizeRiskGraph', () => {
  it('aliases label→name, from_node_id→source, and fills path flags', () => {
    const g = normalizeRiskGraph({
      nodes: [{ id: 1, label: 'db', risk_score: 88, crown_jewel: true }],
      edges: [{ id: 9, from_node_id: 1, to_node_id: 2 }],
    })
    expect(g.nodes[0].name).toBe('db')
    expect(g.nodes[0].severity).toBe('critical')
    expect(g.nodes[0].crown_jewel).toBe(true)
    expect(g.nodes[0].internet_exposed).toBe(false)
    expect(g.edges[0].source).toBe(1)
    expect(g.edges[0].target).toBe(2)
  })
})
