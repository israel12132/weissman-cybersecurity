//! Live knowledge bus — engines ask mid-run what to try next.
//!
//! Static wordlists remain a degraded fallback only. Live paths/hosts/payloads from
//! Sovereign memory (and hydrated `EngineRunContext`) are tried first. No fabricated
//! intel: an empty bus means the static net is used and marked degraded.

use crate::engine_dispatch::EngineRunContext;
use std::future::Future;

tokio::task_local! {
    static LIVE: LiveSlice;
}

#[derive(Debug, Clone, Default)]
pub struct LiveSlice {
    pub paths: Vec<String>,
    pub hosts: Vec<String>,
    pub payloads: Vec<String>,
    pub from_memory: usize,
    pub degraded_static: bool,
}

impl LiveSlice {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.hosts.is_empty() && self.payloads.is_empty()
    }
}

pub fn current() -> LiveSlice {
    LIVE.try_with(Clone::clone).unwrap_or_default()
}

pub async fn scope<F, T>(slice: LiveSlice, fut: F) -> T
where
    F: Future<Output = T>,
{
    LIVE.scope(slice, fut).await
}

/// Live items first, then unique static fallback. Empty live → degraded static-only.
pub fn merge_live_first(live: &[String], fallback: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(live.len() + fallback.len());
    let mut seen = std::collections::HashSet::new();
    for s in live {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    for s in fallback {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

pub fn merge_live_paths(static_paths: Vec<String>) -> Vec<String> {
    let live = current();
    merge_live_first(&live.paths, static_paths)
}

pub fn merge_subdomain_wordlist(apex: &str, static_prefixes: Vec<String>) -> Vec<String> {
    merge_live_first(&live_subdomain_prefixes(apex), static_prefixes)
}

pub fn live_subdomain_prefixes(apex: &str) -> Vec<String> {
    let apex = apex.trim().trim_start_matches('.').to_ascii_lowercase();
    if apex.is_empty() {
        return Vec::new();
    }
    let suffix = format!(".{apex}");
    current()
        .hosts
        .iter()
        .filter_map(|h| {
            let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
            if h == apex {
                return None;
            }
            h.strip_suffix(&suffix)
                .filter(|p| !p.is_empty() && !p.contains('.'))
                .map(str::to_string)
        })
        .collect()
}

pub fn prepend_into_ctx(ctx: &mut EngineRunContext, slice: &LiveSlice) {
    if !slice.paths.is_empty() {
        ctx.discovered_paths =
            merge_live_first(&slice.paths, std::mem::take(&mut ctx.discovered_paths));
    }
    if !slice.hosts.is_empty() {
        ctx.recon_subdomains =
            merge_live_first(&slice.hosts, std::mem::take(&mut ctx.recon_subdomains));
        let extra: Vec<String> = slice
            .hosts
            .iter()
            .map(|h| {
                let h = h.trim();
                if h.starts_with("http://") || h.starts_with("https://") {
                    h.to_string()
                } else {
                    format!("https://{h}")
                }
            })
            .collect();
        ctx.target_list = merge_live_first(&extra, std::mem::take(&mut ctx.target_list));
    }
    if !slice.payloads.is_empty() {
        ctx.memory_payloads =
            merge_live_first(&slice.payloads, std::mem::take(&mut ctx.memory_payloads));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_wins_order() {
        let m = merge_live_first(
            &["/live".into(), "/admin".into()],
            vec!["/admin".into(), "/static".into()],
        );
        assert_eq!(m, vec!["/live", "/admin", "/static"]);
    }

    #[test]
    fn prefixes_from_hosts() {
        LIVE.sync_scope(
            LiveSlice {
                hosts: vec![
                    "api.example.com".into(),
                    "example.com".into(),
                    "cdn.other.net".into(),
                ],
                ..Default::default()
            },
            || {
                let p = live_subdomain_prefixes("example.com");
                assert_eq!(p, vec!["api"]);
            },
        );
    }

    #[tokio::test]
    async fn task_local_paths_win() {
        let slice = LiveSlice {
            paths: vec!["/live-admin".into()],
            ..Default::default()
        };
        let got = scope(slice, async { merge_live_paths(vec!["/static".into()]) }).await;
        assert_eq!(got, vec!["/live-admin", "/static"]);
    }
}
