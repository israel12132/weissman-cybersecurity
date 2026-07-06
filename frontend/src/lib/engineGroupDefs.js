/** Lightweight engine group metadata — safe for tactical boot shell (no full registry). */

export const ENGINE_GROUP_DEFS = [
  { id: 'recon', label: 'Recon & OSINT', color: '#06b6d4' },
  { id: 'web', label: 'Web / API', color: '#8b5cf6' },
  { id: 'ai', label: 'AI / LLM', color: '#ec4899' },
  { id: 'cloud', label: 'Cloud / Infra', color: '#3b82f6' },
  { id: 'ot', label: 'OT / ICS / IoT', color: '#f59e0b' },
  { id: 'stealth', label: 'Stealth / Evasion', color: '#6366f1' },
  { id: 'crypto', label: 'Crypto / Identity', color: '#10b981' },
  { id: 'network', label: 'Network / Protocol', color: '#f97316' },
  { id: 'supply_chain', label: 'Supply Chain', color: '#84cc16' },
  { id: 'apt', label: 'APT / Top-Tier', color: '#ef4444' },
  { id: 'malware', label: 'Malware & Ransomware', color: '#dc2626' },
  { id: 'social', label: 'Social Engineering', color: '#d97706' },
  { id: 'mobile', label: 'Mobile / Apps', color: '#7c3aed' },
  { id: 'data', label: 'Data Exfiltration', color: '#0891b2' },
  { id: 'defense', label: 'Active Defense', color: '#14b8a6' },
]

export const ENGINE_GROUPS = Object.fromEntries(ENGINE_GROUP_DEFS.map((g) => [g.id, g]))
