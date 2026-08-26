//! Board-level executive PDF.
//!
//! Renders via `pdf_report::build_executive_board_pdf`, which emits a self-contained
//! PDF through the Weissman document engine (embedded fonts, bilingual chrome, charts).
//! This deliberately depends on **no** external PDF library: the previous `genpdf` path
//! pulled in `printpdf → lopdf` and the unmaintained `time 0.2.x`.

#[derive(Debug, Clone)]
pub struct ExecutiveBoardParams {
    pub org_label: String,
    pub client_label: Option<String>,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub cloud_finding_count: usize,
    pub soc2_pct: u8,
    pub iso_pct: u8,
    pub gdpr_pct: u8,
}

pub fn render_executive_board_pdf(p: &ExecutiveBoardParams) -> Result<Vec<u8>, String> {
    crate::pdf_report::build_executive_board_pdf(
        &p.org_label,
        p.client_label.as_deref(),
        p.critical,
        p.high,
        p.medium,
        p.low,
        p.cloud_finding_count,
        p.soc2_pct,
        p.iso_pct,
        p.gdpr_pct,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_pdf_without_third_party_pdf_crate() {
        let params = ExecutiveBoardParams {
            org_label: "Weissman Test Org".to_string(),
            client_label: Some("Acme Corp".to_string()),
            critical: 2,
            high: 5,
            medium: 9,
            low: 14,
            cloud_finding_count: 7,
            soc2_pct: 88,
            iso_pct: 91,
            gdpr_pct: 84,
        };
        let bytes = render_executive_board_pdf(&params).expect("PDF render must succeed");
        assert!(bytes.starts_with(b"%PDF-1."), "must be a PDF document");
        assert!(
            bytes.windows(5).any(|w| w == b"%%EOF"),
            "must terminate with %%EOF"
        );
        assert!(bytes.len() > 500, "expected non-trivial PDF body");
    }

    #[test]
    fn renders_without_client_label() {
        let params = ExecutiveBoardParams {
            org_label: "Weissman Test Org".to_string(),
            client_label: None,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            cloud_finding_count: 0,
            soc2_pct: 100,
            iso_pct: 100,
            gdpr_pct: 100,
        };
        let bytes = render_executive_board_pdf(&params).expect("PDF render must succeed");
        assert!(bytes.starts_with(b"%PDF-1."));
    }
}
