//! In-memory LRU + TTL cache for hot external intel responses (reduces NVD/OSV/GitHub API volume).

use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

const NVD_KEYWORD_TTL: Duration = Duration::from_secs(600);
const NVD_RECENT_TTL: Duration = Duration::from_secs(900);
const OSV_TTL: Duration = Duration::from_secs(3600);
const GITHUB_ADV_TTL: Duration = Duration::from_secs(300);

fn cache_capacity() -> u64 {
    std::env::var("WEISSMAN_INTEL_CACHE_MAX_ENTRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8192)
        .max(256)
}

fn nvd_keyword_inner() -> Cache<String, Arc<Vec<u8>>> {
    Cache::builder()
        .max_capacity(cache_capacity())
        .time_to_live(NVD_KEYWORD_TTL)
        .build()
}

fn nvd_recent_inner() -> Cache<String, Arc<Vec<u8>>> {
    Cache::builder()
        .max_capacity(64)
        .time_to_live(NVD_RECENT_TTL)
        .build()
}

fn osv_inner() -> Cache<String, Arc<String>> {
    Cache::builder()
        .max_capacity(cache_capacity())
        .time_to_live(OSV_TTL)
        .build()
}

fn github_adv_inner() -> Cache<String, Arc<Vec<u8>>> {
    Cache::builder()
        .max_capacity(128)
        .time_to_live(GITHUB_ADV_TTL)
        .build()
}

static NVD_KEYWORD_CACHE: std::sync::OnceLock<Cache<String, Arc<Vec<u8>>>> = std::sync::OnceLock::new();
static NVD_RECENT_CACHE: std::sync::OnceLock<Cache<String, Arc<Vec<u8>>>> = std::sync::OnceLock::new();
static OSV_CACHE: std::sync::OnceLock<Cache<String, Arc<String>>> = std::sync::OnceLock::new();
static GITHUB_ADV_CACHE: std::sync::OnceLock<Cache<String, Arc<Vec<u8>>>> = std::sync::OnceLock::new();

pub fn nvd_keyword_cache() -> &'static Cache<String, Arc<Vec<u8>>> {
    NVD_KEYWORD_CACHE.get_or_init(nvd_keyword_inner)
}

pub fn nvd_recent_cache() -> &'static Cache<String, Arc<Vec<u8>>> {
    NVD_RECENT_CACHE.get_or_init(nvd_recent_inner)
}

pub fn osv_summary_cache() -> &'static Cache<String, Arc<String>> {
    OSV_CACHE.get_or_init(osv_inner)
}

pub fn github_advisories_cache() -> &'static Cache<String, Arc<Vec<u8>>> {
    GITHUB_ADV_CACHE.get_or_init(github_adv_inner)
}
