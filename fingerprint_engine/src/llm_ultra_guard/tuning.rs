//! Documented tunables for vLLM, Postgres, Tokio, and the edge brake.
//!
//! Two vLLM profiles exist on purpose:
//! - [`SANITIZATION`] — short, latency-critical Ask Weissman / guard requests
//! - [`SCAN_FUZZ`] — long-context offensive scan/fuzz throughput
//!
//! Never collapse them: dropping `max_num_batched_tokens` on the scan service
//! to 2048 would starve engine fuzzing. The sanitization worker talks to a
//! dedicated vLLM instance (or a LoRA/SLM) configured with these numbers.

#[derive(Debug, Clone, Copy)]
pub struct VllmProfile {
    pub gpu_memory_utilization: f32,
    pub block_size: u32,
    pub max_num_batched_tokens: u32,
    pub max_num_seqs: u32,
    pub max_model_len: u32,
    pub max_tokens: u32,
    pub enable_prefix_caching: bool,
    pub enforce_eager_finish: bool,
    pub trust_remote_code: bool,
    pub disable_log_stats: bool,
    pub swap_space_gib: u32,
    pub continuous_batching: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SanitizationProfile {
    pub fast_path_chars: usize,
    pub max_prompt_chars: usize,
    pub max_decode_depth: u8,
    pub entropy_block: f32,
    pub block_threshold: f32,
    pub quarantine_threshold: f32,
    pub block_threshold_high_risk: f32,
    pub quarantine_threshold_high_risk: f32,
    pub load_shed_ratio: f32,
    pub max_inflight: u32,
    pub tokio_sanitization_connects: u32,
    pub statement_timeout_secs: u32,
}

/// Edge brake + Ask Weissman planner (sub-ms signatures, short completions).
pub const SANITIZATION: SanitizationProfile = SanitizationProfile {
    fast_path_chars: 32,
    max_prompt_chars: 8_000,
    max_decode_depth: 4,
    entropy_block: 5.4,
    block_threshold: 0.72,
    quarantine_threshold: 0.48,
    block_threshold_high_risk: 0.55,
    quarantine_threshold_high_risk: 0.35,
    load_shed_ratio: 0.90,
    max_inflight: 2_048,
    tokio_sanitization_connects: 48,
    statement_timeout_secs: 15,
};

/// Dedicated sanitization vLLM / SLM (not the scan/fuzz endpoint).
pub const VLLM_SANITIZE: VllmProfile = VllmProfile {
    gpu_memory_utilization: 0.90,
    block_size: 16,
    max_num_batched_tokens: 2048,
    max_num_seqs: 256,
    max_model_len: 4096,
    max_tokens: 256,
    enable_prefix_caching: true,
    enforce_eager_finish: true,
    trust_remote_code: false,
    disable_log_stats: true,
    swap_space_gib: 0,
    continuous_batching: true,
};

/// Jailbreak SLM verifier (slightly larger batches).
pub const VLLM_JAILBREAK: VllmProfile = VllmProfile {
    gpu_memory_utilization: 0.90,
    block_size: 16,
    max_num_batched_tokens: 4096,
    max_num_seqs: 256,
    max_model_len: 8192,
    max_tokens: 512,
    enable_prefix_caching: true,
    enforce_eager_finish: true,
    trust_remote_code: false,
    disable_log_stats: true,
    swap_space_gib: 0,
    continuous_batching: true,
};

/// Existing scan/fuzz brain — keep high batched-token ceiling.
pub const SCAN_FUZZ: VllmProfile = VllmProfile {
    gpu_memory_utilization: 0.90,
    block_size: 16,
    max_num_batched_tokens: 65536,
    max_num_seqs: 32,
    max_model_len: 16384,
    max_tokens: 2048,
    enable_prefix_caching: true,
    enforce_eager_finish: true,
    trust_remote_code: false,
    disable_log_stats: true,
    swap_space_gib: 0,
    continuous_batching: true,
};

pub const HNSW_M: i32 = 32;
pub const HNSW_EF_CONSTRUCTION: i32 = 128;
pub const HNSW_EF_SEARCH: i32 = 64;
pub const VECTOR_DIM: usize = 1536;
pub const ANN_LIMIT: i64 = 10;
pub const COSINE_DUP_THRESHOLD: f32 = 0.992;
pub const NORM_LO: f32 = 0.82;
pub const NORM_HI: f32 = 1.18;
pub const OUTLIER_COSINE: f32 = 0.12;

#[must_use]
pub fn vllm_cli_args(p: &VllmProfile) -> Vec<String> {
    vec![
        format!("--gpu-memory-utilization={}", p.gpu_memory_utilization),
        format!("--block-size={}", p.block_size),
        format!("--max-num-batched-tokens={}", p.max_num_batched_tokens),
        format!("--max-num-seqs={}", p.max_num_seqs),
        format!("--max-model-len={}", p.max_model_len),
        format!("--swap-space={}", p.swap_space_gib),
        "--enable-prefix-caching".into(),
        "--disable-log-stats".into(),
    ]
}

#[must_use]
pub fn as_json() -> serde_json::Value {
    serde_json::json!({
        "sanitization": {
            "fast_path_chars": SANITIZATION.fast_path_chars,
            "max_prompt_chars": SANITIZATION.max_prompt_chars,
            "max_decode_depth": SANITIZATION.max_decode_depth,
            "entropy_block": SANITIZATION.entropy_block,
            "block_threshold": SANITIZATION.block_threshold,
            "quarantine_threshold": SANITIZATION.quarantine_threshold,
            "block_threshold_high_risk": SANITIZATION.block_threshold_high_risk,
            "load_shed_ratio": SANITIZATION.load_shed_ratio,
            "max_inflight": SANITIZATION.max_inflight,
            "app_pool_connects": SANITIZATION.tokio_sanitization_connects,
            "statement_timeout_secs": SANITIZATION.statement_timeout_secs,
        },
        "vllm_sanitize": {
            "gpu_memory_utilization": VLLM_SANITIZE.gpu_memory_utilization,
            "block_size": VLLM_SANITIZE.block_size,
            "max_num_batched_tokens": VLLM_SANITIZE.max_num_batched_tokens,
            "max_num_seqs": VLLM_SANITIZE.max_num_seqs,
            "max_model_len": VLLM_SANITIZE.max_model_len,
            "max_tokens": VLLM_SANITIZE.max_tokens,
            "enable_prefix_caching": VLLM_SANITIZE.enable_prefix_caching,
            "enforce_eager_finish": VLLM_SANITIZE.enforce_eager_finish,
            "trust_remote_code": VLLM_SANITIZE.trust_remote_code,
            "cli": vllm_cli_args(&VLLM_SANITIZE),
        },
        "vllm_jailbreak": {
            "max_num_batched_tokens": VLLM_JAILBREAK.max_num_batched_tokens,
            "max_tokens": VLLM_JAILBREAK.max_tokens,
            "cli": vllm_cli_args(&VLLM_JAILBREAK),
        },
        "vllm_scan_fuzz": {
            "max_num_batched_tokens": SCAN_FUZZ.max_num_batched_tokens,
            "max_model_len": SCAN_FUZZ.max_model_len,
            "cli": vllm_cli_args(&SCAN_FUZZ),
        },
        "pgvector": {
            "hnsw_m": HNSW_M,
            "ef_construction": HNSW_EF_CONSTRUCTION,
            "ef_search": HNSW_EF_SEARCH,
            "dim": VECTOR_DIM,
            "ann_limit": ANN_LIMIT,
            "norm_lo": NORM_LO,
            "norm_hi": NORM_HI,
        },
    })
}
