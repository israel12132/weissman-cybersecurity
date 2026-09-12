//! CISA BOD 26-04 risk-triage overlay — **public federal guidance only**.
//!
//! Maps live findings onto the four BOD 26-04 prioritization factors
//! (public exposure, KEV status, exploit automatability, technical impact).
//! Automatability uses FIRST.org EPSS as a documented proxy — never invented
//! CISA automatable flags. No exploit payloads, no dark-web content.

use serde::Serialize;

/// BOD 26-04 highest-risk band: all four factors true.
/// CISA: "as little as three calendar days plus forensic triage".
pub const BOD_P0_SLA: &str = "3 calendar days + forensic triage (BOD 26-04 highest)";
pub const BOD_P1_SLA: &str = "prioritize this week (3 of 4 BOD 26-04 factors)";
pub const BOD_P2_SLA: &str = "risk-based queue (2 of 4 BOD 26-04 factors)";
pub const BOD_P3_SLA: &str = "standard patch cycle (1 of 4 BOD 26-04 factors)";
pub const BOD_P4_SLA: &str = "backlog / informational (0 of 4 BOD 26-04 factors)";

/// EPSS threshold used as the automatable proxy (FIRST.org 30-day exploit probability).
pub const EPSS_AUTOMATABLE_PROXY: f32 = 0.40;

const INTERNET_SOURCES: &[&str] = &[
    "asm",
    "first_mover_surface_delta",
    "first_mover_delta_fusion",
    "leak_hunter",
    "subdomain_takeover",
    "external_exposure_supreme",
    "osint",
    "recon",
    "discovery_engine",
    "dark_web_monitor",
    "typosquatting_monitor",
    "attack_surface_quantify",
    "email_dns_posture",
    "pki_tls",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BodTier {
    P0,
    P1,
    P2,
    P3,
    P4,
}

impl BodTier {
    pub fn sla(self) -> &'static str {
        match self {
            BodTier::P0 => BOD_P0_SLA,
            BodTier::P1 => BOD_P1_SLA,
            BodTier::P2 => BOD_P2_SLA,
            BodTier::P3 => BOD_P3_SLA,
            BodTier::P4 => BOD_P4_SLA,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BodTier::P0 => "P0",
            BodTier::P1 => "P1",
            BodTier::P2 => "P2",
            BodTier::P3 => "P3",
            BodTier::P4 => "P4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BodFactors {
    pub public_exposed: bool,
    pub kev: bool,
    pub automatable: bool,
    pub total_impact: bool,
}

impl BodFactors {
    pub fn score(self) -> u8 {
        u8::from(self.public_exposed)
            + u8::from(self.kev)
            + u8::from(self.automatable)
            + u8::from(self.total_impact)
    }

    pub fn tier(self) -> BodTier {
        match self.score() {
            4 => BodTier::P0,
            3 => BodTier::P1,
            2 => BodTier::P2,
            1 => BodTier::P3,
            _ => BodTier::P4,
        }
    }
}

pub fn source_is_internet_facing(source: &str) -> bool {
    let s = source.trim().to_ascii_lowercase();
    INTERNET_SOURCES.iter().any(|k| *k == s)
}

pub fn public_exposed(source: &str, raw_internet: bool) -> bool {
    raw_internet || source_is_internet_facing(source)
}

pub fn automatable(epss: Option<f32>, verified: bool, kev: bool) -> bool {
    // KEV is "already exploited"; EPSS is likelihood. Either is an honest proxy
    // for CISA "exploit automatable" — documented in the Sources sheet.
    verified || kev || epss.map(|e| e >= EPSS_AUTOMATABLE_PROXY).unwrap_or(false)
}

pub fn total_impact(severity: &str, cvss: Option<f32>) -> bool {
    let s = severity.to_ascii_lowercase();
    s.contains("critical")
        || (s.contains("high") && !s.contains("medium"))
        || cvss.map(|c| c >= 9.0).unwrap_or(false)
}

pub fn classify(
    source: &str,
    raw_internet: bool,
    kev: bool,
    epss: Option<f32>,
    verified: bool,
    severity: &str,
    cvss: Option<f32>,
) -> BodFactors {
    BodFactors {
        public_exposed: public_exposed(source, raw_internet),
        kev,
        automatable: automatable(epss, verified, kev),
        total_impact: total_impact(severity, cvss),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p0_requires_all_four() {
        let f = classify("asm", false, true, Some(0.9), false, "critical", Some(9.8));
        assert!(f.public_exposed && f.kev && f.automatable && f.total_impact);
        assert_eq!(f.tier(), BodTier::P0);
        assert!(f.tier().sla().contains("3 calendar days"));
    }

    #[test]
    fn info_internal_is_p4() {
        let f = classify(
            "k8s_container",
            false,
            false,
            Some(0.01),
            false,
            "info",
            None,
        );
        assert_eq!(f.tier(), BodTier::P4);
        assert_eq!(f.score(), 0);
    }

    #[test]
    fn kev_counts_as_automatable_proxy() {
        let f = classify("iac_misconfig", false, true, None, false, "low", None);
        // kev + automatable(from kev) = 2 → P2
        assert!(f.kev && f.automatable);
        assert_eq!(f.tier(), BodTier::P2);
    }

    #[test]
    fn epss_proxy_threshold() {
        assert!(!automatable(Some(0.39), false, false));
        assert!(automatable(Some(0.40), false, false));
        assert!(automatable(None, true, false));
    }
}
