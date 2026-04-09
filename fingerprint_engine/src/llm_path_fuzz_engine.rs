//! LLM path fuzz — implemented in `weissman-engines` (OpenAI-compatible / vLLM).

use weissman_engines::fuzzer::{run_llm_path_fuzz_result, run_llm_path_fuzz_result_multi};
use weissman_engines::openai_chat::DEFAULT_LLM_BASE_URL;

/// Single-target scan (uses default vLLM base when not configured).
pub async fn run_llm_path_fuzz_result_cli(
    target: &str,
    stealth: Option<&weissman_engines::stealth::StealthConfig>,
    llm_tenant_id: Option<i64>,
) -> weissman_engines::EngineResult {
    run_llm_path_fuzz_result(target, stealth, DEFAULT_LLM_BASE_URL, "", llm_tenant_id).await
}

/// Multi-target + discovered paths; `llm_base_url` should match tenant `llm_base_url` in system_configs.
pub async fn run_llm_path_fuzz_result_multi_cli(
    targets: &[String],
    paths: &[String],
    stealth: Option<&weissman_engines::stealth::StealthConfig>,
    llm_base_url: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> weissman_engines::EngineResult {
    run_llm_path_fuzz_result_multi(
        targets,
        paths,
        stealth,
        llm_base_url,
        llm_model,
        llm_tenant_id,
    )
    .await
}

pub async fn run_llm_path_fuzz_cli(target: &str) {
    let r = run_llm_path_fuzz_result_cli(target, None, None).await;
    weissman_engines::result::print_result(&r);
}
