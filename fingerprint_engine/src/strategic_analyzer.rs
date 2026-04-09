//! StrategicAnalyzer: Attack Path Chaining. Analyzes all findings and asks the LLM how to chain them
//! for full system compromise. The resulting chain is passed to PoE for autonomous execution attempt.

use weissman_engines::openai_chat;

/// Build attack-chain prompt and call OpenAI-compatible LLM (vLLM). Returns the suggested attack chain.
pub async fn synthesize_attack_chain(
    findings_summary: &str,
    target: &str,
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Option<String> {
    if findings_summary.trim().is_empty() {
        return None;
    }
    let prompt = format!(
        r#"You are a Strategic Red Team Lead. Given the following vulnerability findings from a security scan, analyze how they can be CHAINED together to achieve Full System Compromise or maximum impact.

Target: {}
Findings:
{}

Output a concise "Attack Chain" in this exact format:
1. STEP 1: [One-line action using finding X]
2. STEP 2: [Next action building on step 1]
3. ... (as many steps as relevant)
CHAIN_PAYLOAD: [Optional single combined payload or sequence if applicable; else "N/A"]
EXECUTION_ORDER: [Brief note on order of exploitation]

Be specific: reference which finding enables which step. No markdown, no code blocks. Plain text only."#,
        target, findings_summary
    );
    let client = openai_chat::llm_http_client(60);
    let model = openai_chat::resolve_llm_model(llm_model);
    openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.2,
        1024,
        llm_tenant_id,
        "strategic_attack_chain",
        true,
    )
    .await
    .ok()
}
