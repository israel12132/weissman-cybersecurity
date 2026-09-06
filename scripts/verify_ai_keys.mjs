#!/usr/bin/env node
/**
 * Advisory: report which LLM / enrichment API keys are present in the process
 * environment. Never prints secret values — only names and whether they are set.
 *
 * Exit 0 always (advisory). Prints JSON to stdout.
 */
const LLM_KEYS = [
  'WEISSMAN_LLM_API_KEY',
  'WEISSMAN_LLM_BASE_URL',
  'WEISSMAN_LLM_MODEL',
  'WEISSMAN_LLM_ENDPOINTS',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'GEMINI_API_KEY',
  'AZURE_OPENAI_API_KEY',
  'AZURE_OPENAI_ENDPOINT',
  'AZURE_OPENAI_DEPLOYMENT',
  'GROQ_API_KEY',
  'MISTRAL_API_KEY',
  'DEEPSEEK_API_KEY',
  'OPENROUTER_API_KEY',
  'TOGETHER_API_KEY',
  'XAI_API_KEY',
  'PERPLEXITY_API_KEY',
  'FIREWORKS_API_KEY',
  'COHERE_API_KEY',
  'OLLAMA_HOST',
]

const ENRICHMENT_KEYS = [
  'WEISSMAN_SHODAN_API_KEY',
  'SHODAN_API_KEY',
  'CENSYS_API_ID',
  'CENSYS_API_SECRET',
  'NVD_API_KEY',
  'WEISSMAN_NVD_API_KEY',
  'GITHUB_TOKEN',
  'WEISSMAN_GITHUB_TOKEN',
]

function present(name) {
  const v = process.env[name]
  return typeof v === 'string' && v.trim().length > 0
}

const llm = LLM_KEYS.map((name) => ({ name, set: present(name) }))
const enrichment = ENRICHMENT_KEYS.map((name) => ({ name, set: present(name) }))
const anyLlm = llm.some((k) => k.set && k.name.endsWith('_API_KEY'))
  || present('WEISSMAN_LLM_BASE_URL')
  || present('OLLAMA_HOST')

const report = {
  advisory: true,
  ready: anyLlm,
  llm,
  enrichment,
  missing_llm: llm.filter((k) => !k.set).map((k) => k.name),
  note: 'Set any one provider key (or WEISSMAN_LLM_BASE_URL for local vLLM) and restart weissman-server. See docs/operations/AI-KEYS.md.',
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
if (!anyLlm) {
  process.stderr.write('verify_ai_keys: no LLM provider key or local base URL is set (advisory)\n')
}
process.exit(0)
