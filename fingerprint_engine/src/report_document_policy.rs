//! Document-level security policy for server-rendered HTML deliverables (Report Studio).
//!
//! The Command Center opens a report by fetching it with the JWT and handing the bytes to a
//! `blob:` URL (`frontend/src/lib/downloadClientReport.js`). A `blob:` document never sees the
//! HTTP response headers of the fetch, so a `Content-Security-Policy` *header* alone protects
//! only direct navigations. The policy therefore also travels **inside** the document as a
//! `<meta http-equiv>` tag, which browsers honour for `blob:`, `file:` and print contexts alike.
//! Both forms carry the same string so behaviour is identical whichever path served the bytes.
//!
//! The policy matches exactly what `report_studio` emits — inline `<style>`, `data:` fonts,
//! inline SVG, `data:` images, plain `<a href>` links — and forbids everything else: no scripts,
//! no external fetches, no form submission, no `<base>` rewriting.

/// The policy string, shared by the response header and the in-document `<meta>` tag.
pub const REPORT_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; \
                              img-src data:; base-uri 'none'; form-action 'none'";

/// Inject the policy as the first child of `<head>` so it applies before any other element is
/// parsed. Idempotent: a document that already carries the tag is returned unchanged. A document
/// without a `<head>` (never produced by Report Studio) is returned unchanged rather than mangled.
pub fn inject_document_csp(html: String) -> String {
    if html.contains("http-equiv=\"Content-Security-Policy\"") {
        return html;
    }
    let tag = format!("<meta http-equiv=\"Content-Security-Policy\" content=\"{REPORT_CSP}\">");
    // Match `<head>` and `<head lang=..>` / `<head dir=..>` variants case-insensitively.
    let lower = html.to_ascii_lowercase();
    let Some(start) = lower.find("<head") else {
        return html;
    };
    let Some(close_rel) = lower[start..].find('>') else {
        return html;
    };
    let insert_at = start + close_rel + 1;
    let mut out = String::with_capacity(html.len() + tag.len());
    out.push_str(&html[..insert_at]);
    out.push_str(&tag);
    out.push_str(&html[insert_at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_meta_as_first_head_child() {
        let doc =
            "<!doctype html><html><head><title>x</title></head><body></body></html>".to_string();
        let out = inject_document_csp(doc);
        let head = out.find("<head>").unwrap() + "<head>".len();
        assert!(out[head..].starts_with("<meta http-equiv=\"Content-Security-Policy\""));
        assert!(out.contains(REPORT_CSP));
        assert_eq!(
            out.matches("http-equiv=\"Content-Security-Policy\"")
                .count(),
            1
        );
    }

    #[test]
    fn idempotent_and_tolerates_head_attributes() {
        let doc = "<html><HEAD lang=\"he\"><meta charset=\"utf-8\"></HEAD></html>".to_string();
        let once = inject_document_csp(doc);
        assert!(once.contains("<HEAD lang=\"he\"><meta http-equiv=\"Content-Security-Policy\""));
        let twice = inject_document_csp(once.clone());
        assert_eq!(once, twice);
    }

    #[test]
    fn leaves_headless_fragment_untouched() {
        let frag = "<p>no head here</p>".to_string();
        assert_eq!(inject_document_csp(frag.clone()), frag);
    }

    #[test]
    fn policy_forbids_scripts_and_external_fetches() {
        assert!(REPORT_CSP.starts_with("default-src 'none'"));
        for directive in ["script-src", "connect-src", "frame-src", "object-src"] {
            // Not granted explicitly → falls back to default-src 'none'.
            assert!(
                !REPORT_CSP.contains(directive),
                "{directive} must not be granted"
            );
        }
        assert!(REPORT_CSP.contains("style-src 'unsafe-inline'"));
        assert!(REPORT_CSP.contains("font-src data:"));
        assert!(REPORT_CSP.contains("base-uri 'none'"));
        assert!(REPORT_CSP.contains("form-action 'none'"));
    }

    #[test]
    fn report_studio_output_gets_the_policy_and_stays_self_contained() {
        let meta = crate::report_studio::ReportMeta {
            client_name: "Acme".into(),
            brand_name: None,
            report_id: "R-1".into(),
            version: "1.0".into(),
            generated_at: "2026-09-26".into(),
            assessment_window: None,
            assessment_type: None,
            scope_assets: Vec::new(),
            exclusions: Vec::new(),
            roe_mode: None,
            crypto_hash: None,
            verify_url: None,
            contact_email: None,
        };
        let html = crate::report_studio::render_client_report_html(
            &meta,
            &[],
            crate::report_studio::Lang::En,
        );
        let out = inject_document_csp(html);
        assert!(out.contains("<meta http-equiv=\"Content-Security-Policy\""));
        assert!(!out.contains("<script"));
        assert!(!out.contains("<link"));
    }
}
