//! RAG poisoning verification: L2-norm, cosine, SHA-256 integrity, outlier vs centroid.

use crate::llm_ultra_guard::tuning::{
    unit_norm_ok, COSINE_DUP_THRESHOLD, NORM_UNIT_EPSILON, OUTLIER_COSINE, VECTOR_DIM,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingVerdict {
    pub ok: bool,
    pub l2_norm: f32,
    pub sha256: String,
    pub outlier: bool,
    pub reason: String,
    pub flags: u32,
}

/// Verify a 1536-d embedding before it is written to `supreme_council_memory`.
#[must_use]
pub fn verify_embedding(vec: &[f32], centroid: Option<&[f32]>) -> EmbeddingVerdict {
    if vec.len() != VECTOR_DIM {
        return EmbeddingVerdict {
            ok: false,
            l2_norm: 0.0,
            sha256: String::new(),
            outlier: true,
            reason: format!("dimension {} != {VECTOR_DIM}", vec.len()),
            flags: crate::llm_ultra_guard::flags::RAG_OUTLIER,
        };
    }
    if !vec.iter().all(|x| x.is_finite()) {
        return EmbeddingVerdict {
            ok: false,
            l2_norm: 0.0,
            sha256: String::new(),
            outlier: true,
            reason: "non-finite component".into(),
            flags: crate::llm_ultra_guard::flags::RAG_OUTLIER,
        };
    }
    let n = l2_norm(vec);
    let mut flags = 0u32;
    let mut reasons = Vec::new();
    // Architect gate: never `n == 1.0`. FP16/FP32 and CUDA vs CPU jitter is
    // bounded by NORM_UNIT_EPSILON (1e-5). Anything outside is poison or a
    // caller that skipped l2_normalize().
    if !unit_norm_ok(n) {
        flags |= crate::llm_ultra_guard::flags::RAG_OUTLIER;
        reasons.push(format!(
            "l2_norm {n:.8} is not 1±{NORM_UNIT_EPSILON} (FP jitter bound)"
        ));
    }
    let mut outlier = false;
    if let Some(c) = centroid {
        if c.len() == vec.len() {
            let cos = cosine(vec, c);
            if cos < OUTLIER_COSINE {
                outlier = true;
                flags |= crate::llm_ultra_guard::flags::RAG_OUTLIER;
                reasons.push(format!("cosine-to-centroid {cos:.4} < {OUTLIER_COSINE}"));
            }
        }
    }
    let sha = sha256_vec(vec);
    let ok = flags == 0;
    if !ok {
        outlier = true;
    }
    EmbeddingVerdict {
        ok,
        l2_norm: n,
        sha256: sha,
        outlier,
        reason: if reasons.is_empty() {
            "ok".into()
        } else {
            reasons.join("; ")
        },
        flags,
    }
}

#[must_use]
pub fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

#[must_use]
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    // Chunked so rustc can autovectorize (AVX-512 when the host enables it).
    let (aa, bb) = (&a[..n], &b[..n]);
    for (x, y) in aa.iter().zip(bb.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

#[must_use]
pub fn sha256_vec(v: &[f32]) -> String {
    let mut hasher = Sha256::new();
    for x in v {
        hasher.update(x.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

#[must_use]
pub fn too_similar_to_known_false_positive(candidate: &[f32], known_fp: &[Vec<f32>]) -> bool {
    known_fp
        .iter()
        .any(|k| cosine(candidate, k) >= COSINE_DUP_THRESHOLD)
}

/// L2-normalise in place (up to two passes so residual error stays inside ε).
/// Returns false if the vector is zero.
pub fn l2_normalize(v: &mut [f32]) -> bool {
    if !scale_to_unit(v) {
        return false;
    }
    if !unit_norm_ok(l2_norm(v)) {
        let _ = scale_to_unit(v);
    }
    true
}

fn scale_to_unit(v: &mut [f32]) -> bool {
    let n = l2_norm(v);
    if n < 1e-12 {
        return false;
    }
    for x in v.iter_mut() {
        *x /= n;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_dim() {
        let v = vec![0.1; 8];
        let r = verify_embedding(&v, None);
        assert!(!r.ok);
    }

    #[test]
    fn accepts_unitish_vector() {
        let mut v = vec![0.0f32; VECTOR_DIM];
        v[0] = 1.0;
        let r = verify_embedding(&v, None);
        assert!(r.ok, "{}", r.reason);
        assert!((r.l2_norm - 1.0).abs() < 1e-5);
        assert_eq!(r.sha256.len(), 64);
    }

    #[test]
    fn cosine_self_is_one() {
        let mut v = vec![0.0f32; VECTOR_DIM];
        v[3] = 0.6;
        v[7] = 0.8;
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn accepts_fp_jitter_around_unit() {
        let mut hi = vec![0.0f32; VECTOR_DIM];
        hi[0] = 1.0 + NORM_UNIT_EPSILON * 0.5;
        let r = verify_embedding(&hi, None);
        assert!(r.ok, "1+ε/2 must pass: {}", r.reason);

        let mut lo = vec![0.0f32; VECTOR_DIM];
        lo[0] = 1.0 - NORM_UNIT_EPSILON * 0.5;
        let r = verify_embedding(&lo, None);
        assert!(r.ok, "1-ε/2 must pass: {}", r.reason);
    }

    #[test]
    fn rejects_unnormalized_and_exact_one_is_not_required() {
        let mut collapsed = vec![0.0f32; VECTOR_DIM];
        collapsed[0] = 0.99;
        assert!(!verify_embedding(&collapsed, None).ok);

        let mut unit = vec![0.0f32; VECTOR_DIM];
        unit[0] = 1.0;
        assert!(verify_embedding(&unit, None).ok);

        let mut raw = vec![0.25f32; VECTOR_DIM];
        assert!(l2_normalize(&mut raw));
        let r = verify_embedding(&raw, None);
        assert!(r.ok, "post-normalize must sit inside ε: n={} {}", r.l2_norm, r.reason);
        assert!(unit_norm_ok(r.l2_norm));
    }

    #[test]
    fn rejects_near_duplicate_of_known_false_positive() {
        let mut v = vec![0.0f32; VECTOR_DIM];
        v[0] = 1.0;
        assert!(too_similar_to_known_false_positive(&v, &[v.clone()]));
        let mut other = vec![0.0f32; VECTOR_DIM];
        other[1] = 1.0;
        assert!(!too_similar_to_known_false_positive(&other, &[v]));
    }
}
