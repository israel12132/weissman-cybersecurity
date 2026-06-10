import { ENGINES_BY_ID } from './enginesRegistry'

export const TOP_TIER_ENGINE_IDS = [
  'nexus_sovereign_swarm',
  'kill_chain',
  'oast_oob',
  'deception_honeypot',
  'digital_twin',
  'zero_day_prediction',
  'threat_emulation',
  'poe_synthesis',
  'satellite_recon',
  'darkweb_intel',
  'financial_osint',
  'blockchain_trace',
  'metadata_harvest',
  'patent_recon',
  'telecom_osint',
  'iot_shodan_scan',
  'job_posting_osint',
  'github_secret_scan',
  'graphql_deep_attack',
  'grpc_reflection_attack',
  'http2_attack',
]

const BASE_EXPECTED_OUTPUTS = [
  'Actionable findings with severity and remediation context',
  'Evidence trail suitable for analyst review and report generation',
  'Machine-readable JSON fields for downstream orchestration',
]

const PROFILES = {
  nexus_sovereign_swarm: {
    mission: 'Deploy thousands of autonomous AI micro-agents across the full attack surface with emergent hive-mind consensus — breakthrough swarm intelligence no competitor offers.',
    intelligenceFocus: 'Multi-archetype agent coordination (Scout/Exploiter/Correlator/Stealth/Oracle), cross-signal consensus, endpoint agent bridging, edge POP distribution, Swarm IQ scoring.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Swarm metrics with SIQ score', 'Hive-mind consensus findings', 'Oracle LLM strategic synthesis'],
    samplePayload: {
      engine: 'nexus_sovereign_swarm',
      target: 'https://target.example',
      agent_count: 2048,
      hive_mode: 'emergent',
      llm_strategy: 'adaptive',
      endpoint_bridge: 'true',
      edge_distribution: 'true',
      convergence_threshold: '0.85',
    },
  },
  kill_chain: {
    mission: 'Build full adversary path from recon to impact to prioritize breakpoints.',
    intelligenceFocus: 'Attack-path sequencing, choke points, lateral movement opportunities.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Mapped kill-chain stage transitions'],
    samplePayload: { engine: 'kill_chain', target: 'https://target.example' },
  },
  oast_oob: {
    mission: 'Detect blind injection channels using out-of-band callbacks.',
    intelligenceFocus: 'DNS/HTTP callback signals, token correlation, proof-of-exploit evidence.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Verified OAST callback events'],
    samplePayload: { engine: 'oast_oob', target: 'https://target.example' },
  },
  deception_honeypot: {
    mission: 'Identify deception infrastructure and honeypot signatures before deeper ops.',
    intelligenceFocus: 'Header fingerprints, interaction anomalies, environment consistency checks.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Honeypot likelihood score and indicators'],
    samplePayload: { engine: 'deception_honeypot', target: 'https://target.example' },
  },
  digital_twin: {
    mission: 'Build environment model from live signals to guide high-yield follow-up scans.',
    intelligenceFocus: 'Stack headers, policy posture, protocol behavior profile.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Digital twin profile snapshot'],
    samplePayload: { engine: 'digital_twin', target: 'https://target.example' },
  },
  zero_day_prediction: {
    mission: 'Estimate high-probability emerging risk areas from stack and behavior telemetry.',
    intelligenceFocus: 'Technology fingerprinting, weak hardening patterns, exploitability hints.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Prediction rationale with confidence signals'],
    samplePayload: { engine: 'zero_day_prediction', target: 'https://target.example' },
  },
  threat_emulation: {
    mission: 'Simulate adversary tradecraft to stress controls across the attack lifecycle.',
    intelligenceFocus: 'Control bypass likelihood, detection gaps, response readiness.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Emulation scenario trace and outcomes'],
    samplePayload: { engine: 'threat_emulation', target: 'https://target.example' },
  },
  poe_synthesis: {
    mission: 'Generate proof-of-exploit synthesis package with structured verification context.',
    intelligenceFocus: 'PoE narrative quality, reproducibility cues, validation artifacts.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'PoE synthesis stream and status timeline'],
    samplePayload: { engine: 'poe_synthesis', target: 'https://target.example' },
  },
  satellite_recon: {
    mission: 'Extended external reconnaissance for broad surface expansion signals.',
    intelligenceFocus: 'Domain and infrastructure expansion from multi-source recon.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Expanded recon entities and links'],
    samplePayload: { engine: 'satellite_recon', target: 'https://target.example' },
  },
  darkweb_intel: {
    mission: 'Track threat chatter and exposed assets in darkweb-adjacent intelligence flows.',
    intelligenceFocus: 'Credential leakage, actor mentions, exposed references to tenant assets.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Leak/intel correlation summary'],
    samplePayload: { engine: 'darkweb_intel', target: 'https://target.example' },
  },
  financial_osint: {
    mission: 'Extract finance-adjacent public exposure intelligence relevant to attack planning.',
    intelligenceFocus: 'Public filings, vendor exposure, organizational risk signals.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Finance-risk intelligence snapshot'],
    samplePayload: { engine: 'financial_osint', target: 'https://target.example' },
  },
  blockchain_trace: {
    mission: 'Correlate blockchain artifacts with threat infrastructure indicators.',
    intelligenceFocus: 'Wallet/address clues linked to campaigns and laundering paths.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Trace graph hints and linked indicators'],
    samplePayload: { engine: 'blockchain_trace', target: 'https://target.example' },
  },
  metadata_harvest: {
    mission: 'Harvest metadata leaks to enrich target context and attack-path hypotheses.',
    intelligenceFocus: 'Document, header, and service metadata footprints.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Metadata leak inventory'],
    samplePayload: { engine: 'metadata_harvest', target: 'https://target.example' },
  },
  patent_recon: {
    mission: 'Use patent/public innovation signals to infer likely technology stack and risks.',
    intelligenceFocus: 'Technology disclosures and inferred architecture patterns.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Tech inference summary from public records'],
    samplePayload: { engine: 'patent_recon', target: 'https://target.example' },
  },
  telecom_osint: {
    mission: 'Collect telecom exposure intelligence around network and provider dependencies.',
    intelligenceFocus: 'Carrier signals, telecom metadata, dependency attack surface clues.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Telecom exposure matrix'],
    samplePayload: { engine: 'telecom_osint', target: 'https://target.example' },
  },
  iot_shodan_scan: {
    mission: 'Identify internet-visible IoT footprint and weak posture indicators.',
    intelligenceFocus: 'Exposed devices, protocol posture, firmware/service banners.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'IoT external exposure list'],
    samplePayload: { engine: 'iot_shodan_scan', target: 'https://target.example' },
  },
  job_posting_osint: {
    mission: 'Infer internal stack and process exposure from hiring signal intelligence.',
    intelligenceFocus: 'Tech stack clues from role requirements and public hiring trends.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Hiring-derived technology profile'],
    samplePayload: { engine: 'job_posting_osint', target: 'https://target.example' },
  },
  github_secret_scan: {
    mission: 'Hunt secret leakage and repository exposure linked to target domain and org.',
    intelligenceFocus: 'Credential patterns, token leaks, hardcoded key references.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'Leak indicators mapped to repos/entities'],
    samplePayload: { engine: 'github_secret_scan', target: 'https://target.example' },
  },
  graphql_deep_attack: {
    mission: 'Perform deep GraphQL abuse scenarios mapped to modern API attack patterns.',
    intelligenceFocus: 'Schema abuse, depth/cost bypass, nested authorization weaknesses.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'GraphQL exploitation traces and weak nodes'],
    samplePayload: { engine: 'graphql_deep_attack', target: 'https://target.example' },
  },
  grpc_reflection_attack: {
    mission: 'Probe gRPC reflection and service exposure to identify high-risk entry points.',
    intelligenceFocus: 'Reflection exposure, service enumeration, transport hardening gaps.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'gRPC reflection and service findings'],
    samplePayload: { engine: 'grpc_reflection_attack', target: 'https://target.example' },
  },
  http2_attack: {
    mission: 'Stress HTTP/2 protocol handling for desync and request-manipulation weaknesses.',
    intelligenceFocus: 'Protocol edge cases, stream handling bugs, desynchronization behavior.',
    expectedOutputs: [...BASE_EXPECTED_OUTPUTS, 'HTTP/2 risk scenarios and evidence'],
    samplePayload: { engine: 'http2_attack', target: 'https://target.example' },
  },
}

export function getTopTierProfile(engineId) {
  const baseEngine = ENGINES_BY_ID[engineId] || null
  const profile = PROFILES[engineId] || null
  if (!profile || !baseEngine) return null
  return {
    ...profile,
    id: engineId,
    label: baseEngine.label,
    mitre: baseEngine.mitre,
    description: baseEngine.description,
    requiresTarget: !!baseEngine.requiresTarget,
  }
}

export function isTopTierEngine(engineId) {
  return TOP_TIER_ENGINE_IDS.includes(engineId)
}
