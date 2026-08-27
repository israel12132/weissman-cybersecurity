//! Hard caps for any Ask Weissman path that might touch pgvector / RAG memory.
//!
//! `supreme_council_memory` and other embedding tables are **not** on the NL allow-list.
//! These helpers exist so a future vector operator cannot run unbounded ANN: k is clamped
//! to 5 and neighbors farther than [`MAX_COSINE_DISTANCE`] are dropped.

/// Maximum nearest neighbors returned from a vector probe (k-NN).
pub const MAX_K: i64 = 5;
/// Maximum pgvector cosine distance (`<=>`) accepted for a retrieved neighbor.
/// 0.0 is identical; ~2.0 is opposite. 0.45 keeps only reasonably close hits and
/// prevents a "scan the whole index" retrieval.
pub const MAX_COSINE_DISTANCE: f64 = 0.45;

const BLOCKED_VECTOR_TABLES: &[&str] = &[
    "supreme_council_memory",
    "supreme_council_rag_hits",
    "pentest_winning_paths",
];

/// True for tables that store embeddings / RAG memory and must never be NL-queried.
#[must_use]
pub fn is_blocked_vector_table(name: &str) -> bool {
    let n = name.trim();
    BLOCKED_VECTOR_TABLES.iter().any(|t| *t == n)
        || n.contains("embedding")
        || n.ends_with("_memory")
        || n.contains("vector")
}

/// Clamp a requested k to `(1..=MAX_K)`.
#[must_use]
pub fn clamp_k(k: i64) -> i64 {
    k.clamp(1, MAX_K)
}

/// True when `cosine_distance` is within the allowed retrieval ball.
#[must_use]
pub fn neighbor_allowed(cosine_distance: f64) -> bool {
    cosine_distance.is_finite() && cosine_distance >= 0.0 && cosine_distance <= MAX_COSINE_DISTANCE
}

/// Keep at most [`MAX_K`] neighbors that pass the distance cap, preserving input order.
#[must_use]
pub fn cap_neighbors(distances: &[f64], requested_k: i64) -> Vec<(usize, f64)> {
    let k = clamp_k(requested_k) as usize;
    distances
        .iter()
        .enumerate()
        .filter(|(_, d)| neighbor_allowed(**d))
        .take(k)
        .map(|(i, d)| (i, *d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_rag_and_embedding_table_names() {
        assert!(is_blocked_vector_table("supreme_council_memory"));
        assert!(is_blocked_vector_table("pentest_winning_paths"));
        assert!(is_blocked_vector_table("client_embeddings"));
        assert!(is_blocked_vector_table("foo_vector_idx"));
        assert!(!is_blocked_vector_table("vulnerabilities"));
        assert!(!is_blocked_vector_table("clients"));
    }

    #[test]
    fn k_and_distance_caps() {
        assert_eq!(clamp_k(99), 5);
        assert_eq!(clamp_k(0), 1);
        assert_eq!(clamp_k(3), 3);
        assert!(neighbor_allowed(0.0));
        assert!(neighbor_allowed(0.45));
        assert!(!neighbor_allowed(0.46));
        assert!(!neighbor_allowed(-0.01));
        assert!(!neighbor_allowed(f64::NAN));
    }

    #[test]
    fn cap_neighbors_drops_far_hits_and_honors_k() {
        let d = [0.1, 0.9, 0.2, 0.3, 0.4, 0.11, 0.12];
        let kept = cap_neighbors(&d, 99);
        assert_eq!(kept.len(), 5);
        assert!(kept.iter().all(|(_, dist)| *dist <= MAX_COSINE_DISTANCE));
        assert_eq!(kept[0], (0, 0.1));
        assert!(!kept.iter().any(|(i, _)| *i == 1));
    }
}
