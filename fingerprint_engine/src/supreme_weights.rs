//! Supreme Brain Part 6 — deterministic edge-weight, FAIR, and RAG scoring.
//!
//! All path / dollar / memory math used by the attack-path inference engine,
//! the FAIR blast-radius model, and the RAG council lives here so the formulas
//! are unit-testable without Postgres. Dijkstra itself stays in `attack_path`.
//!
//! Fixed-point: edge costs are stored as **milli-cost** (`i64`, 1/1000 of a
//! cost unit) so BinaryHeap comparisons never depend on float rounding.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Milli-cost scale (1.000 cost unit = 1000 milli).
pub const MILLI: i64 = 1000;

/// Saturating milli-cost add — overflow must never panic a worker thread.
#[inline]
pub fn add_milli_cost(current_cost: i64, edge_cost: i64) -> i64 {
    current_cost.checked_add(edge_cost).unwrap_or(i64::MAX)
}
/// Dijkstra hop ceiling — combinatorial fuse for graphs with hundreds of thousands of nodes.
pub const MAX_PATH_DEPTH: usize = 12;
/// Path aging: edges not re-validated within this many days lose relevance.
pub const PATH_AGING_DAYS: f64 = 7.0;
/// KEV listed CVEs subtract this from the edge weight (shortest-path priority).
pub const KEV_WEIGHT_DELTA: f64 = 0.8;
/// Weissman Agent presence multiplies edge weight (UEBA / local detection = harder pivot).
pub const AGENT_WEIGHT_MULT: f64 = 2.5;
/// Cross-region (e.g. IL ↔ US-East) extra network-control difficulty.
pub const CROSS_REGION_MULT: f64 = 1.75;
/// Annualised rate of occurrence floor for CISA KEV.
pub const KEV_ARO_FLOOR: f64 = 1.0;
/// Probability floor for zero-days with no EPSS.
pub const ZERO_DAY_PROB_FLOOR: f64 = 0.1;
/// ARO cannot exceed one event per month on average.
pub const ARO_CAP: f64 = 12.0;
/// Cosine similarity above this is treated as a duplicate RAG vector.
pub const VECTOR_DEDUP_COSINE: f32 = 0.99;
/// Memory half-life used by RAG decay (days).
pub const MEMORY_HALFLIFE_DAYS: f64 = 365.0;
/// Time-aware RAG: memories newer than this get a distance bonus.
pub const RAG_RECENCY_YEARS: f64 = 2.0;

/// Inputs that determine a single graph-edge cost.
#[derive(Debug, Clone, Copy)]
pub struct EdgeWeightInputs {
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub agent_present: bool,
    pub honey_node: bool,
    pub age_days: f64,
    pub cross_region: bool,
    pub identity_edge: bool,
    /// 0.5 ..= 1.0 — probe / engine evidence quality.
    pub engine_confidence: f32,
    /// Absolute UEBA z-score on the destination node (0 if unknown).
    pub ueba_zscore: f32,
    pub false_positive: bool,
}

impl Default for EdgeWeightInputs {
    fn default() -> Self {
        Self {
            cvss: 0.0,
            epss: 0.0,
            kev: false,
            agent_present: false,
            honey_node: false,
            age_days: 0.0,
            cross_region: false,
            identity_edge: false,
            engine_confidence: 1.0,
            ueba_zscore: 0.0,
            false_positive: false,
        }
    }
}

#[inline]
pub fn to_milli(x: f64) -> i64 {
    (x * MILLI as f64).round() as i64
}

#[inline]
pub fn milli_to_f64(m: i64) -> f64 {
    m as f64 / MILLI as f64
}

/// Logarithmic CVSS ease in 0 ..= 1. Higher CVSS → easier attacker pivot.
pub fn cvss_log_ease(cvss: f32) -> f64 {
    let cvss = (cvss as f64).clamp(0.0, 10.0);
    (1.0 + cvss).log2() / 11.0_f64.log2()
}

/// Engine-confidence from evidence quality (KEV > EPSS > CVSS-only > none).
pub fn evidence_confidence(cvss: f32, epss: f32, kev: bool) -> f32 {
    if kev {
        1.0
    } else if epss > 0.0 {
        0.85
    } else if cvss > 0.0 {
        0.70
    } else {
        0.50
    }
}

/// Dijkstra edge weight. Lower = easier lateral movement (shortest-path logic).
pub fn edge_weight_milli(i: &EdgeWeightInputs) -> i64 {
    if i.false_positive {
        return to_milli(50.0);
    }
    let ease = cvss_log_ease(i.cvss).max(0.08);
    let mut w = 1.0 / ease;
    let epss = (i.epss as f64).clamp(0.0, 1.0);
    w *= (1.0 - epss).max(0.05);
    let conf = (i.engine_confidence as f64).clamp(0.50, 1.0);
    w /= conf;
    if i.kev {
        w = (w - KEV_WEIGHT_DELTA).max(0.01);
    }
    if i.agent_present {
        w *= AGENT_WEIGHT_MULT;
    }
    if i.honey_node {
        w *= 8.0;
    }
    if i.age_days > PATH_AGING_DAYS {
        let extra = ((i.age_days - PATH_AGING_DAYS) / 30.0).min(2.0);
        w *= 1.0 + extra * 0.25;
    }
    if i.cross_region {
        w *= CROSS_REGION_MULT;
    }
    if i.identity_edge {
        w *= 1.35;
    }
    if i.ueba_zscore.abs() > 2.0 {
        w *= 0.85;
    }
    to_milli(w.max(0.01))
}

pub fn edge_weight(i: &EdgeWeightInputs) -> f64 {
    milli_to_f64(edge_weight_milli(i))
}

/// Regions that imply a WAN / control-plane hop (harder than same-region).
pub fn is_cross_region(from: &str, to: &str) -> bool {
    let a = from.trim().to_ascii_uppercase();
    let b = to.trim().to_ascii_uppercase();
    if a.is_empty() || b.is_empty() || a == b {
        return false;
    }
    fn zone(r: &str) -> &str {
        if r.starts_with("IL") || r.contains("ISRAEL") {
            "il"
        } else if r.starts_with("US") || r.contains("EAST") || r.contains("WEST") {
            "us"
        } else if r.starts_with("EU") {
            "eu"
        } else {
            r
        }
    }
    zone(&a) != zone(&b)
}

pub fn is_identity_edge(edge_type: &str) -> bool {
    matches!(
        edge_type,
        "has_permission" | "authenticates" | "assumes_role" | "iam"
    )
}

pub fn is_smb_or_port_edge(edge_type: &str, ports: &[u16]) -> bool {
    let et = edge_type.to_ascii_lowercase();
    if et.contains("smb") || et.contains("445") || et.contains("139") {
        return true;
    }
    ports.iter().any(|p| et.contains(&p.to_string()))
}

/// Path score 0 ..= 100 for the CEO dashboard (normalised likelihood × jewel factor).
pub fn path_score_0_100(cost: f64, jewel_asset_value: f32, kev_hops: usize) -> u8 {
    let likelihood = (1.0 / (1.0 + cost.max(0.0))).clamp(0.0, 1.0);
    let jewel = (jewel_asset_value as f64).clamp(0.5, 3.0);
    let kev_boost = 1.0 + (kev_hops.min(4) as f64) * 0.05;
    ((likelihood * 100.0 * jewel * kev_boost) / 3.0)
        .round()
        .clamp(0.0, 100.0) as u8
}

// ── FAIR ────────────────────────────────────────────────────────────────────

/// Single Loss Expectancy = asset_value × max(CVSS/10, 0.5). Never exceeds asset value.
pub fn single_loss_expectancy(asset_value_usd: i64, cvss: f32) -> i64 {
    if asset_value_usd <= 0 {
        return 0;
    }
    let lm = (cvss as f64 / 10.0).clamp(0.5, 1.0);
    let sle = ((asset_value_usd as f64) * lm).round() as i64;
    sle.min(asset_value_usd)
}

/// True when a finding looks like a zero-day (severe, no EPSS, not KEV).
pub fn is_zero_day(cvss: f32, epss: f32, kev: bool) -> bool {
    !kev && epss <= 0.0 && cvss >= 9.0
}

/// Annualised Rate of Occurrence. KEV floors at 1.0/yr. Zero-day floors at 0.1.
pub fn annual_rate_of_occurrence(epss: f32, kev: bool, zero_day: bool) -> f64 {
    let mut aro = (epss as f64).clamp(0.0, 1.0) * ARO_CAP;
    if kev {
        aro = aro.max(KEV_ARO_FLOOR);
    }
    if zero_day {
        aro = aro.max(ZERO_DAY_PROB_FLOOR);
    }
    if epss >= 0.9 {
        aro = aro.max((epss as f64) * ARO_CAP);
    }
    aro.clamp(0.0, ARO_CAP)
}

/// Annualised Loss Expectancy. Agent-healthy assets receive a risk discount.
///
/// Hard FAIR cap: ALE cannot exceed `asset_value_usd`. A destroyed or stolen
/// asset cannot cost more than its own value unless secondary cascades are
/// already folded into that value.
pub fn annual_loss_expectancy(
    sle_usd: i64,
    epss: f32,
    kev: bool,
    discount: f32,
    agent_present: bool,
    zero_day: bool,
    asset_value_usd: i64,
) -> i64 {
    if sle_usd <= 0 {
        return 0;
    }
    let mut disc = (discount as f64).clamp(0.0, 1.0);
    if agent_present {
        disc *= 0.55;
    }
    let aro = annual_rate_of_occurrence(epss, kev, zero_day);
    let raw = ((sle_usd as f64) * aro * disc).round() as i64;
    ale_board_cap(raw, asset_value_usd)
}

/// Conservative board cap: ALE cannot exceed the asset's absolute value.
pub fn ale_board_cap(ale_usd: i64, asset_value_usd: i64) -> i64 {
    if asset_value_usd <= 0 {
        return 0;
    }
    ale_usd.min(asset_value_usd)
}

/// Daily cost of leaving a finding unpatched (ALE / 365).
pub fn cost_of_delay_per_day(ale_usd: i64) -> i64 {
    if ale_usd <= 0 {
        return 0;
    }
    ((ale_usd as f64) / 365.0).round() as i64
}

/// Countermeasure ROI: ALE saved if this node is patched (100% of node ALE).
pub fn countermeasure_roi_usd(node_ale_usd: i64) -> i64 {
    node_ale_usd.max(0)
}

/// Share of total ALE sitting on the single largest contributor (0 ..= 100).
pub fn concentration_pct(top_ale: i64, total_ale: i64) -> u8 {
    if total_ale <= 0 {
        return 0;
    }
    (((top_ale as f64) / (total_ale as f64)) * 100.0)
        .round()
        .clamp(0.0, 100.0) as u8
}

/// Business-interruption add-on: estimated hours of downtime × hourly value.
pub fn business_interruption_usd(asset_value_usd: i64, downtime_hours: f64) -> i64 {
    if asset_value_usd <= 0 || downtime_hours <= 0.0 {
        return 0;
    }
    let hourly = (asset_value_usd as f64) / (365.0 * 8.0);
    (hourly * downtime_hours).round() as i64
}

// ── RAG / pentest memory ────────────────────────────────────────────────────

pub fn memory_decay(age_days: f64) -> f64 {
    if age_days <= 0.0 {
        return 1.0;
    }
    (-age_days / MEMORY_HALFLIFE_DAYS).exp()
}

/// Time-aware additive penalty on cosine *distance* (smaller distance = closer).
pub fn rag_recency_penalty(age_days: f64) -> f64 {
    let recency_days = RAG_RECENCY_YEARS * 365.0;
    if age_days <= recency_days {
        0.0
    } else {
        0.15
    }
}

pub fn is_duplicate_vector(cosine_similarity: f32) -> bool {
    cosine_similarity > VECTOR_DEDUP_COSINE
}

/// SHA-256 of the f32 LE bytes — integrity of stored vector bytes.
pub fn embedding_checksum(v: &[f32]) -> String {
    let mut h = Sha256::new();
    for x in v {
        h.update(x.to_le_bytes());
    }
    hex::encode(h.finalize())
}

pub fn checksum_matches(v: &[f32], expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    expected.eq_ignore_ascii_case(&embedding_checksum(v))
}

/// True when `s` is exactly 32 bytes encoded as 64 ASCII hex characters.
#[must_use]
pub fn is_rag_provenance_hex64(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// HMAC key for RAG / pentest-memory provenance.
///
/// Strict (`WEISSMAN_ENV=production` or `WEISSMAN_E2E_STACK=1`): **only**
/// `WEISSMAN_RAG_PROVENANCE_SECRET` (64 hex, loaded from the vault). No fallback
/// to JWT or council signing keys. Empty key means fail-closed: nothing is signed
/// or accepted.
///
/// Local / unit tests: dedicated secret, then council signing secret, then JWT,
/// with a one-shot WARNING so a laptop boot never requires minting 64 hex.
pub fn rag_provenance_secret() -> Vec<u8> {
    let dedicated = std::env::var("WEISSMAN_RAG_PROVENANCE_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if crate::security_startup::rag_hmac_must_be_strict() {
        return dedicated.unwrap_or_default().into_bytes();
    }
    if dedicated
        .as_deref()
        .map(is_rag_provenance_hex64)
        .unwrap_or(false)
    {
        return dedicated.unwrap_or_default().into_bytes();
    }
    let _ = crate::security_startup::enforce_rag_provenance_policy();
    dedicated
        .or_else(|| {
            std::env::var("WEISSMAN_COUNCIL_DEBATE_SIGNING_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            std::env::var("WEISSMAN_JWT_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default()
        .into_bytes()
}

fn rag_provenance_mac_input(
    tenant_id: i64,
    kind: &str,
    issuer: &str,
    source: &str,
    checksum: &str,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(64 + kind.len() + issuer.len() + source.len() + checksum.len());
    buf.extend_from_slice(b"WEISSMAN_RAG_PROV_V1|");
    buf.extend_from_slice(tenant_id.to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(kind.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(issuer.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(source.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(checksum.as_bytes());
    buf
}

/// Sign a vector row so retrieval can reject unsigned / injected embeddings.
pub fn sign_rag_provenance(
    tenant_id: i64,
    kind: &str,
    issuer: &str,
    source: &str,
    checksum: &str,
) -> String {
    let key = rag_provenance_secret();
    if key.is_empty() || checksum.is_empty() {
        return String::new();
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
        return String::new();
    };
    mac.update(&rag_provenance_mac_input(
        tenant_id, kind, issuer, source, checksum,
    ));
    hex::encode(mac.finalize().into_bytes())
}

/// Fail-closed HMAC verify. Empty secret, empty MAC, or mismatch → reject.
pub fn verify_rag_provenance(
    tenant_id: i64,
    kind: &str,
    issuer: &str,
    source: &str,
    checksum: &str,
    provided_hex: &str,
) -> bool {
    if provided_hex.is_empty() || checksum.is_empty() {
        return false;
    }
    let key = rag_provenance_secret();
    if key.is_empty() {
        return false;
    }
    let Ok(sig) = hex::decode(provided_hex.trim()) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
        return false;
    };
    mac.update(&rag_provenance_mac_input(
        tenant_id, kind, issuer, source, checksum,
    ));
    mac.verify_slice(&sig).is_ok()
}

pub const RAG_PROVENANCE_ENGINE: &str = "engine";
pub const RAG_PROVENANCE_ANALYST: &str = "analyst";

/// Replay-hit reinforcement: multiply retrieval weight after a confirmed win.
pub fn payload_reinforcement(won_count: i32, replay_hit_rate: f32) -> f64 {
    let wins = (won_count.max(1) as f64).ln_1p();
    let hit = (replay_hit_rate as f64).clamp(0.0, 1.0);
    (1.0 + wins * 0.15) * (1.0 + hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> EdgeWeightInputs {
        EdgeWeightInputs {
            cvss: 5.0,
            epss: 0.2,
            ..EdgeWeightInputs::default()
        }
    }

    #[test]
    fn kev_lowers_weight() {
        let mut a = base();
        let mut b = base();
        a.kev = true;
        b.kev = false;
        assert!(edge_weight_milli(&a) < edge_weight_milli(&b));
    }

    #[test]
    fn agent_multiplies_weight_by_2_5() {
        let mut clean = EdgeWeightInputs {
            cvss: 5.0,
            epss: 0.0,
            engine_confidence: 1.0,
            ..EdgeWeightInputs::default()
        };
        let without = edge_weight(&clean);
        clean.agent_present = true;
        let with = edge_weight(&clean);
        let ratio = with / without;
        assert!((ratio - AGENT_WEIGHT_MULT).abs() < 0.02, "ratio={ratio}");
    }

    #[test]
    fn higher_epss_lowers_weight() {
        let mut low = base();
        let mut high = base();
        low.epss = 0.1;
        high.epss = 0.9;
        assert!(edge_weight_milli(&high) < edge_weight_milli(&low));
    }

    #[test]
    fn cvss_log_ease_monotone() {
        assert!(cvss_log_ease(9.8) > cvss_log_ease(4.0));
        assert!(cvss_log_ease(4.0) > cvss_log_ease(0.0));
        assert!(cvss_log_ease(0.0) >= 0.0);
    }

    #[test]
    fn honey_node_is_expensive() {
        let mut n = base();
        let cheap = edge_weight_milli(&n);
        n.honey_node = true;
        assert!(edge_weight_milli(&n) > cheap * 4);
    }

    #[test]
    fn false_positive_pruned_as_expensive() {
        let mut n = base();
        n.false_positive = true;
        assert!(edge_weight_milli(&n) >= to_milli(50.0));
    }

    #[test]
    fn path_aging_increases_weight() {
        let mut fresh = base();
        let mut stale = base();
        fresh.age_days = 1.0;
        stale.age_days = 40.0;
        assert!(edge_weight_milli(&stale) > edge_weight_milli(&fresh));
    }

    #[test]
    fn cross_region_il_us() {
        assert!(is_cross_region("IL", "US-EAST-1"));
        assert!(!is_cross_region("US-EAST-1", "us-east-1"));
        assert!(!is_cross_region("", "US-EAST-1"));
    }

    #[test]
    fn path_score_clamps() {
        assert_eq!(path_score_0_100(0.0, 3.0, 4), 100);
        assert!(path_score_0_100(50.0, 1.0, 0) < 10);
    }

    #[test]
    fn sle_floors_at_half_and_caps_at_value() {
        assert_eq!(single_loss_expectancy(100_000, 0.0), 50_000);
        assert_eq!(single_loss_expectancy(100_000, 10.0), 100_000);
        assert_eq!(single_loss_expectancy(100_000, 9.8), 98_000);
        assert_eq!(single_loss_expectancy(-5, 9.8), 0);
    }

    #[test]
    fn kev_aro_floor_is_one() {
        assert_eq!(annual_rate_of_occurrence(0.0, true, false), KEV_ARO_FLOOR);
        assert_eq!(annual_rate_of_occurrence(0.0, false, false), 0.0);
        assert_eq!(
            annual_rate_of_occurrence(0.0, false, true),
            ZERO_DAY_PROB_FLOOR
        );
        assert_eq!(annual_rate_of_occurrence(1.0, true, false), ARO_CAP);
    }

    #[test]
    fn ale_agent_discount_and_kev_floor() {
        let sle = 100_000;
        let no_agent = annual_loss_expectancy(sle, 0.0, true, 0.30, false, false, 100_000);
        let agent = annual_loss_expectancy(sle, 0.0, true, 0.30, true, false, 100_000);
        assert_eq!(no_agent, 30_000);
        assert!(agent < no_agent);
        assert_eq!(agent, 16_500);
    }

    #[test]
    fn ale_never_exceeds_asset_value() {
        // Uncapped math is $100k × 12 ARO × 1.0 = $1.2M — FAIR forbids that.
        let ale = annual_loss_expectancy(100_000, 1.0, true, 1.0, false, false, 100_000);
        assert_eq!(ale, 100_000);
        assert_eq!(ale_board_cap(1_200_000, 100_000), 100_000);
        assert_eq!(ale_board_cap(20_000, 100_000), 20_000);
    }

    #[test]
    fn milli_cost_add_never_panics_on_overflow() {
        assert_eq!(add_milli_cost(i64::MAX, 1), i64::MAX);
        assert_eq!(add_milli_cost(i64::MAX - 5, 10), i64::MAX);
        assert_eq!(add_milli_cost(1_000, 250), 1_250);
    }

    #[test]
    fn cost_of_delay_and_roi() {
        assert_eq!(cost_of_delay_per_day(365_000), 1_000);
        assert_eq!(countermeasure_roi_usd(42_000), 42_000);
        assert_eq!(concentration_pct(40, 100), 40);
        assert_eq!(concentration_pct(1, 0), 0);
    }

    #[test]
    fn milli_roundtrip() {
        let m = to_milli(1.234);
        assert!((milli_to_f64(m) - 1.234).abs() < 0.001);
    }

    #[test]
    fn memory_decay_and_dedup() {
        assert!((memory_decay(0.0) - 1.0).abs() < 1e-9);
        assert!(memory_decay(365.0) < 0.40);
        assert!(is_duplicate_vector(0.995));
        assert!(!is_duplicate_vector(0.90));
        assert_eq!(rag_recency_penalty(10.0), 0.0);
        assert_eq!(rag_recency_penalty(900.0), 0.15);
    }

    #[test]
    fn embedding_checksum_stable() {
        let v = vec![0.1_f32, 0.2, 0.3];
        let a = embedding_checksum(&v);
        let b = embedding_checksum(&v);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(checksum_matches(&v, &a));
        assert!(!checksum_matches(&v, "deadbeef"));
        assert!(!checksum_matches(&v, ""), "empty checksum is fail-closed");
    }

    #[test]
    fn rag_provenance_hmac_roundtrip_and_reject() {
        std::env::set_var(
            "WEISSMAN_RAG_PROVENANCE_SECRET",
            "unit-test-rag-provenance-secret-32b!!",
        );
        let chk = embedding_checksum(&[0.1, 0.2, 0.3]);
        let mac = sign_rag_provenance(
            7,
            RAG_PROVENANCE_ENGINE,
            "supreme_council",
            "oast_success",
            &chk,
        );
        assert!(!mac.is_empty());
        assert!(verify_rag_provenance(
            7,
            RAG_PROVENANCE_ENGINE,
            "supreme_council",
            "oast_success",
            &chk,
            &mac
        ));
        assert!(!verify_rag_provenance(
            7,
            RAG_PROVENANCE_ENGINE,
            "supreme_council",
            "oast_success",
            &chk,
            "deadbeef"
        ));
        assert!(!verify_rag_provenance(
            8,
            RAG_PROVENANCE_ENGINE,
            "supreme_council",
            "oast_success",
            &chk,
            &mac
        ));
        std::env::remove_var("WEISSMAN_RAG_PROVENANCE_SECRET");
    }

    #[test]
    fn rag_provenance_hex64_rejects_wrong_shapes() {
        assert!(is_rag_provenance_hex64(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_rag_provenance_hex64("short"));
        assert!(!is_rag_provenance_hex64(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
        ));
        assert!(!is_rag_provenance_hex64(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
        ));
    }

    #[test]
    fn reinforcement_grows_with_wins() {
        let cold = payload_reinforcement(1, 0.0);
        let hot = payload_reinforcement(12, 0.8);
        assert!(hot > cold);
    }

    #[test]
    fn smb_port_matcher() {
        assert!(is_smb_or_port_edge("smb_connects", &[445]));
        assert!(is_smb_or_port_edge("connects:445", &[22, 445]));
        assert!(!is_smb_or_port_edge("https", &[445]));
    }
}
