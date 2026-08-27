//! Board-level executive PDF.
//!
//! Renders via `pdf_report::build_executive_board_pdf`, which emits a self-contained
//! `%PDF-1.4` document using the standard base-14 Helvetica font (no font embedding,
//! no third-party PDF crate). This deliberately depends on **no** external PDF library:
//! the previous `genpdf` path pulled in `printpdf → lopdf` and the unmaintained
//! `time 0.2.x`, adding avoidable supply-chain surface — including the `lopdf`
//! parse-DoS advisory (RUSTSEC-2026-0187), which is cleared by dropping genpdf.
//! Since we only ever *generate* these reports and base-14 Helvetica is universally
//! available in every conformant PDF viewer, the native writer covers the use case
//! without any of that supply-chain surface.

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
    /// FAIR USD blast-radius line (or cannot-price). Never a linear-product dollar.
    pub fair_line: Option<String>,
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
        p.fair_line.as_deref(),
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
            fair_line: Some("FAIR USD blast-radius  ALE $180,000  ·  worst-case SLE $98,000".into()),
        };
        let bytes = render_executive_board_pdf(&params).expect("PDF render must succeed");
        assert!(bytes.starts_with(b"%PDF-1.4"), "must be a PDF-1.4 document");
        assert!(bytes.ends_with(b"%%EOF\n"), "must terminate with %%EOF");
        assert!(bytes.len() > 500, "expected non-trivial PDF body");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("FAIR USD blast-radius") || text.contains("ALE"));
        assert!(!text.contains("severity_weight"));
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
            fair_line: Some("Cannot price — FAIR inputs missing".into()),
        };
        let bytes = render_executive_board_pdf(&params).expect("PDF render must succeed");
        assert!(bytes.starts_with(b"%PDF-1.4"));
    }
}
