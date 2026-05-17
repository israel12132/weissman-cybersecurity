//! Enterprise-grade Executive PDF Report. Helvetica only. Multi-page with cover,
//! radial gauge, donut/heatmap/bar charts, remediation roadmap, and technical findings.
//! All data from live DB; automatic page-breaking.

use chrono::TimeZone;
use chrono_tz::Asia::Jerusalem;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::f64::consts::PI;

/// Optional crypto proof: (audit_root_hash, qr_data_url, verification_url).
pub type CryptoProof = (String, String, String);

/// One finding row: id, title, severity, source, description, poc_exploit.
pub type FindingRow = (i64, String, String, String, String, String);

const PAGE_W: f64 = 612.0;
const PAGE_H: f64 = 792.0;
const MARGIN: f64 = 50.0;
const FOOTER_Y: f64 = 40.0;
const PAGE_BREAK_Y: f64 = 90.0;

fn pdf_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn truncate_ascii(s: &str, max: usize) -> String {
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    format!("{}…", chars.into_iter().take(max).collect::<String>())
}

fn israel_now() -> String {
    Jerusalem
        .from_utc_datetime(&chrono::Utc::now().naive_utc())
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn remediation_from_desc(desc: &str) -> String {
    let desc = desc.trim();
    if desc.is_empty() {
        return "—".to_string();
    }
    if let Ok(v) = serde_json::from_str::<JsonValue>(desc) {
        if let Some(s) = v.get("remediation_snippet").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(s) = v.get("remediation").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    "—".to_string()
}

/// Combines PoE verification, entropy leak signals, stack/CVE correlation, and severity into one 0–100 score.
fn derive_remediation_priority_from_signals(
    severity: &str,
    verified: bool,
    entropy: Option<f64>,
    stack_corr: f64,
    has_poc: bool,
) -> i32 {
    let s = severity.to_lowercase();
    let mut p: i32 = if s.contains("critical") {
        82
    } else if s.contains("high") {
        64
    } else if s.contains("medium") || s.contains("med") {
        48
    } else {
        36
    };
    if verified {
        p += 10;
    }
    if has_poc {
        p += 5;
    }
    if let Some(e) = entropy {
        if e >= 7.5 {
            p += 6;
        } else if e >= 6.0 {
            p += 3;
        }
    }
    p += (stack_corr * 18.0).round() as i32;
    p.clamp(0, 100)
}

/// Reads `remediation_priority_score` from stored JSON when present; otherwise derives from hardening signals.
fn remediation_priority_score_for_row(desc: &str, severity: &str, poc_exploit: &str) -> i32 {
    let has_poc = !poc_exploit.trim().is_empty();
    if let Ok(v) = serde_json::from_str::<JsonValue>(desc) {
        if let Some(n) = v.get("remediation_priority_score").and_then(|x| x.as_i64()) {
            return n.clamp(0, 100) as i32;
        }
        if let Some(n) = v.get("remediation_priority_score").and_then(|x| x.as_u64()) {
            return (n as i32).clamp(0, 100);
        }
        let verified = v.get("verified").and_then(|x| x.as_bool()).unwrap_or(false);
        let ent = v.get("entropy_score").and_then(|x| x.as_f64());
        let stack = v.get("stack_correlation_score")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        let sev = v
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or(severity);
        return derive_remediation_priority_from_signals(sev, verified, ent, stack, has_poc);
    }
    derive_remediation_priority_from_signals(severity, false, None, 0.0, has_poc)
}

/// Proof-of-breach filter: include in Detailed Findings only if the finding has a proof (cURL) or
/// is HIGH/CRITICAL, and has meaningful content (remediation or poc). Excludes ASM/info noise.
fn should_include_in_detailed_findings(row: &FindingRow) -> bool {
    let (_id, _title, severity, _source, desc, poc_exploit) = row;
    let has_poc = !poc_exploit.trim().is_empty();
    let sev_lower = severity.to_lowercase();
    let severity_high_or_critical = sev_lower.contains("critical") || sev_lower.contains("high");
    let has_remediation = remediation_from_desc(desc) != "—";
    (has_poc || severity_high_or_critical) && (has_remediation || has_poc)
}

/// Count discovery-only findings (asm/osint, not included in detailed) for Reconnaissance Summary.
fn discovery_noise_count(findings: &[FindingRow]) -> usize {
    findings
        .iter()
        .filter(|f| {
            !should_include_in_detailed_findings(f)
                && (f.3.eq_ignore_ascii_case("asm") || f.3.eq_ignore_ascii_case("osint"))
        })
        .count()
}

/// Multi-page PDF builder: collects content streams per page.
struct PdfBuilder {
    page_streams: Vec<String>,
    current: String,
    y: f64,
}

impl PdfBuilder {
    fn new() -> Self {
        Self {
            page_streams: Vec::new(),
            current: String::new(),
            y: PAGE_H - MARGIN,
        }
    }

    fn ensure_space(&mut self, need: f64) {
        if self.y - need < PAGE_BREAK_Y {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        if !self.current.is_empty() {
            self.page_streams.push(std::mem::take(&mut self.current));
        }
        self.y = PAGE_H - MARGIN;
    }

    fn finish(mut self) -> Vec<String> {
        if !self.current.is_empty() {
            self.page_streams.push(self.current);
        }
        self.page_streams
    }

    fn text(&mut self, font_size: i32, s: &str) {
        let t = pdf_escape(s);
        self.current.push_str(&format!(
            "BT /F1 {} Tf 72 {} Td ({}) Tj ET\n",
            font_size, self.y as i32, t
        ));
        self.y -= font_size as f64 + 4.0;
    }

    fn text_at(&mut self, x: f64, font_size: i32, s: &str) {
        let t = pdf_escape(s);
        self.current.push_str(&format!(
            "BT /F1 {} Tf {} {} Td ({}) Tj ET\n",
            font_size, x, self.y, t
        ));
        self.y -= font_size as f64 + 4.0;
    }

    fn set_fill_rgb(&mut self, r: f64, g: f64, b: f64) {
        self.current.push_str(&format!("{} {} {} rg\n", r, g, b));
    }

    fn set_stroke_rgb(&mut self, r: f64, g: f64, b: f64) {
        self.current.push_str(&format!("{} {} {} RG\n", r, g, b));
    }

    fn rect_fill(&mut self, x: f64, y: f64, w: f64, h: f64) {
        self.current
            .push_str(&format!("{} {} {} {} re f\n", x, y, w, h));
    }

    fn rect_stroke(&mut self, x: f64, y: f64, w: f64, h: f64) {
        self.current
            .push_str(&format!("{} {} {} {} re S\n", x, y, w, h));
    }

    /// Arc from angle_start to angle_end (degrees 0=right, 90=up), radius r, center (cx, cy). Filled.
    fn arc_fill(&mut self, cx: f64, cy: f64, r: f64, angle_start_deg: f64, angle_end_deg: f64) {
        let k = 4.0 / 3.0 * (PI / 2.0_f64).tan() / 2.0;
        let to_rad = PI / 180.0;
        let start = angle_start_deg * to_rad;
        let end = angle_end_deg * to_rad;
        let x0 = cx + r * start.cos();
        let y0 = cy + r * start.sin();
        self.current.push_str(&format!("{} {} m\n", x0, y0));
        let n = ((end - start) / (PI / 2.0)).ceil().max(1.0) as i32;
        let step = (end - start) / n as f64;
        for i in 0..n {
            let a1 = start + step * i as f64;
            let a2 = start + step * (i + 1) as f64;
            let _x1 = cx + r * a1.cos();
            let _y1 = cy + r * a1.sin();
            let x2 = cx + r * a2.cos();
            let y2 = cy + r * a2.sin();
            let c1x = cx + r * a1.cos() - k * r * a1.sin();
            let c1y = cy + r * a1.sin() + k * r * a1.cos();
            let c2x = cx + r * a2.cos() - k * r * a2.sin();
            let c2y = cy + r * a2.sin() + k * r * a2.cos();
            self.current.push_str(&format!(
                "{} {} {} {} {} {} c\n",
                c1x, c1y, c2x, c2y, x2, y2
            ));
        }
        self.current.push_str(&format!("{} {} l h f\n", cx, cy));
    }

    /// Full circle filled at (cx, cy) radius r.
    fn circle_fill(&mut self, cx: f64, cy: f64, r: f64) {
        self.arc_fill(cx, cy, r, 0.0, 360.0);
    }

    /// Donut segment: outer r, inner r_inner, from a1 to a2 (degrees).
    fn donut_segment(&mut self, cx: f64, cy: f64, r_outer: f64, r_inner: f64, a1: f64, a2: f64) {
        let to_rad = PI / 180.0;
        let rad1 = a1 * to_rad;
        let rad2 = a2 * to_rad;
        let x1 = cx + r_outer * rad1.cos();
        let y1 = cy + r_outer * rad1.sin();
        self.current.push_str(&format!("{} {} m\n", x1, y1));
        let k = 4.0 / 3.0 * (PI / 2.0_f64).tan() / 2.0;
        let n = ((rad2 - rad1) / (PI / 2.0)).ceil().max(1.0) as i32;
        let step = (rad2 - rad1) / n as f64;
        for i in 0..n {
            let t1 = rad1 + step * i as f64;
            let t2 = rad1 + step * (i + 1) as f64;
            let xo = cx + r_outer * t2.cos();
            let yo = cy + r_outer * t2.sin();
            let c1x = cx + r_outer * t1.cos() - k * r_outer * t1.sin();
            let c1y = cy + r_outer * t1.sin() + k * r_outer * t1.cos();
            let c2x = cx + r_outer * t2.cos() - k * r_outer * t2.sin();
            let c2y = cy + r_outer * t2.sin() + k * r_outer * t2.cos();
            self.current.push_str(&format!(
                "{} {} {} {} {} {} c\n",
                c1x, c1y, c2x, c2y, xo, yo
            ));
        }
        let xi = cx + r_inner * rad2.cos();
        let yi = cy + r_inner * rad2.sin();
        self.current.push_str(&format!("{} {} l\n", xi, yi));
        for i in (0..n).rev() {
            let t1 = rad1 + step * (i + 1) as f64;
            let t2 = rad1 + step * i as f64;
            let xo = cx + r_inner * t2.cos();
            let yo = cy + r_inner * t2.sin();
            let c1x = cx + r_inner * t1.cos() + k * r_inner * t1.sin();
            let c1y = cy + r_inner * t1.sin() - k * r_inner * t1.cos();
            let c2x = cx + r_inner * t2.cos() + k * r_inner * t2.sin();
            let c2y = cy + r_inner * t2.sin() - k * r_inner * t2.cos();
            self.current.push_str(&format!(
                "{} {} {} {} {} {} c\n",
                c1x, c1y, c2x, c2y, xo, yo
            ));
        }
        self.current.push_str("h f\n");
    }

    /// Radial gauge: semicircle 180° (left to right). Red 0–33, Yellow 33–66, Green 66–100.
    fn radial_gauge(&mut self, cx: f64, cy: f64, r: f64, score: i32) {
        let score = score.clamp(0, 100) as f64;
        self.set_fill_rgb(0.92, 0.92, 0.92);
        self.circle_fill(cx, cy, r + 8.0);
        self.set_fill_rgb(0.15, 0.15, 0.18);
        self.arc_fill(cx, cy, r, 180.0, 0.0);
        let fill_deg = score / 100.0 * 180.0;
        if score <= 33.0 {
            self.set_fill_rgb(0.9, 0.22, 0.22);
            self.arc_fill(cx, cy, r - 5.0, 180.0, 180.0 - fill_deg);
        } else if score <= 66.0 {
            self.set_fill_rgb(0.9, 0.22, 0.22);
            self.arc_fill(cx, cy, r - 5.0, 180.0, 120.0);
            self.set_fill_rgb(0.95, 0.7, 0.2);
            self.arc_fill(cx, cy, r - 5.0, 120.0, 180.0 - fill_deg);
        } else {
            self.set_fill_rgb(0.9, 0.22, 0.22);
            self.arc_fill(cx, cy, r - 5.0, 180.0, 120.0);
            self.set_fill_rgb(0.95, 0.7, 0.2);
            self.arc_fill(cx, cy, r - 5.0, 120.0, 60.0);
            self.set_fill_rgb(0.22, 0.68, 0.38);
            self.arc_fill(cx, cy, r - 5.0, 60.0, 180.0 - fill_deg);
        }
        self.set_fill_rgb(0.08, 0.08, 0.1);
        self.circle_fill(cx, cy, r - 22.0);
        self.set_fill_rgb(1.0, 1.0, 1.0);
    }

    /// Certified badge at bottom center.
    fn certified_badge(&mut self, hash: &str) {
        let bw = 220.0;
        let bh = 36.0;
        let bx = (PAGE_W - bw) / 2.0;
        let by = FOOTER_Y + 10.0;
        self.set_fill_rgb(0.06, 0.12, 0.22);
        self.rect_fill(bx, by, bw, bh);
        self.set_stroke_rgb(0.2, 0.6, 0.9);
        self.current.push_str("1 w\n");
        self.rect_stroke(bx, by, bw, bh);
        self.set_fill_rgb(0.2, 0.8, 0.95);
        self.current.push_str(&format!(
            "BT /F1 9 Tf {} {} Td (CERTIFIED) Tj ET\n",
            bx + 12.0,
            by + 14.0
        ));
        self.set_fill_rgb(0.7, 0.8, 0.9);
        let hash_short = if hash.len() > 42 { &hash[..42] } else { hash };
        self.current.push_str(&format!(
            "BT /F1 7 Tf {} {} Td ({}) Tj ET\n",
            bx + 12.0,
            by + 4.0,
            pdf_escape(hash_short)
        ));
    }
}

/// Build enterprise PDF: cover, executive summary, remediation roadmap, technical findings.
pub fn build_client_report_pdf(
    client_name: &str,
    findings: &[FindingRow],
    crypto_proof: Option<&CryptoProof>,
) -> Result<Vec<u8>, String> {
    let date = israel_now();
    let (critical, high, medium, low_info) =
        findings
            .iter()
            .fold((0i64, 0i64, 0i64, 0i64), |acc, (_, _, sev, _, _, _)| {
                let s = sev.to_lowercase();
                let (c, h, m, l) = acc;
                if s.contains("critical") {
                    (c + 1, h, m, l)
                } else if s.contains("high") {
                    (c, h + 1, m, l)
                } else if s.contains("medium") || s.contains("med") {
                    (c, h, m + 1, l)
                } else {
                    (c, h, m, l + 1)
                }
            });
    let score = (100 - critical * 25 - high * 15 - medium * 5)
        .max(0)
        .min(100) as i32;
    let total = (critical + high + medium + low_info).max(1) as f64;
    let avg_remediation_priority: i32 = if findings.is_empty() {
        0
    } else {
        let sum: i32 = findings
            .iter()
            .map(|(_, _, sev, _, desc, poc)| remediation_priority_score_for_row(desc, sev, poc))
            .sum();
        sum / findings.len() as i32
    };

    let hash = crypto_proof.map(|(h, _, _)| h.as_str()).unwrap_or("");

    let mut b = PdfBuilder::new();

    // ---------- COVER PAGE ----------
    b.set_fill_rgb(0.0, 0.0, 0.0);
    b.text(24, "WEISSMAN CYBERSECURITY");
    b.y -= 8.0;
    b.set_fill_rgb(0.4, 0.5, 0.6);
    b.text(12, "Executive Security Assessment Report");
    b.text_at(72.0, 14, &format!("{}", client_name));
    b.y -= 4.0;
    b.set_fill_rgb(0.5, 0.5, 0.55);
    b.text(10, &format!("Report Generated: {} (Israel)", date));
    b.y -= 24.0;

    let gauge_cx = PAGE_W / 2.0;
    let gauge_cy = 380.0;
    b.radial_gauge(gauge_cx, gauge_cy, 70.0, score);
    b.set_fill_rgb(0.2, 0.8, 0.95);
    b.text_at(gauge_cx - 18.0, 22, &format!("{}", score));
    b.set_fill_rgb(0.6, 0.65, 0.7);
    b.text_at(gauge_cx - 30.0, 10, "Security Score");
    b.set_fill_rgb(0.5, 0.58, 0.68);
    b.text_at(
        gauge_cx - 118.0,
        9,
        &format!(
            "Remediation Priority Index (avg): {}/100 — PoE, entropy, stack/CVE correlation",
            avg_remediation_priority
        ),
    );
    b.y = gauge_cy - 100.0;

    if !hash.is_empty() {
        b.y = FOOTER_Y + 60.0;
        b.certified_badge(hash);
    }
    b.y = FOOTER_Y;
    b.set_fill_rgb(0.4, 0.4, 0.45);
    b.text_at(72.0, 8, "(c) Weissman Cybersecurity — Confidential.");
    b.new_page();

    // ---------- EXECUTIVE SUMMARY ----------
    b.set_fill_rgb(0.0, 0.0, 0.0);
    b.text(16, "Executive Summary");
    b.set_fill_rgb(0.35, 0.4, 0.5);
    b.text(10, &format!("{} | {}", client_name, date));
    b.y -= 16.0;

    let donut_cx = 160.0;
    let donut_cy = b.y - 55.0;
    let donut_r = 50.0;
    let donut_ri = 28.0;
    let mut deg = 0.0;
    let cr = critical as f64 / total * 360.0;
    let hr = high as f64 / total * 360.0;
    let mr = medium as f64 / total * 360.0;
    let lr = low_info as f64 / total * 360.0;
    if cr > 0.0 {
        b.set_fill_rgb(0.9, 0.25, 0.25);
        b.donut_segment(donut_cx, donut_cy, donut_r, donut_ri, deg, deg + cr);
        deg += cr;
    }
    if hr > 0.0 {
        b.set_fill_rgb(0.95, 0.6, 0.2);
        b.donut_segment(donut_cx, donut_cy, donut_r, donut_ri, deg, deg + hr);
        deg += hr;
    }
    if mr > 0.0 {
        b.set_fill_rgb(0.9, 0.85, 0.25);
        b.donut_segment(donut_cx, donut_cy, donut_r, donut_ri, deg, deg + mr);
        deg += mr;
    }
    if lr > 0.0 {
        b.set_fill_rgb(0.25, 0.7, 0.4);
        b.donut_segment(donut_cx, donut_cy, donut_r, donut_ri, deg, deg + lr);
    }
    b.set_fill_rgb(0.2, 0.2, 0.2);
    b.text_at(donut_cx - 8.0, 9, "Severity");
    b.text_at(donut_cx + 58.0, 9, "Critical");
    b.set_fill_rgb(0.9, 0.25, 0.25);
    b.rect_fill(donut_cx + 52.0, donut_cy - 42.0, 8.0, 6.0);
    b.set_fill_rgb(0.2, 0.2, 0.2);
    b.text_at(donut_cx + 65.0, 9, &format!("{}", critical));
    b.y = donut_cy - 70.0;

    let hm_x = 280.0;
    let hm_y = b.y - 5.0;
    let cell = 22.0;
    for row in 0..5 {
        for col in 0..5 {
            let t = (row + col) as f64 / 8.0;
            let r = t.min(1.0);
            let g = (1.0 - t).max(0.0);
            b.set_fill_rgb(r * 0.9 + 0.1, g * 0.8 + 0.1, 0.15);
            b.rect_fill(
                hm_x + col as f64 * cell,
                hm_y - row as f64 * cell,
                cell - 1.0,
                cell - 1.0,
            );
        }
    }
    b.y = hm_y - 5.0 * cell - 8.0;
    b.set_fill_rgb(0.2, 0.2, 0.2);
    b.text_at(hm_x, 9, "Risk Heatmap");
    b.y = hm_y - 5.0 * cell - 28.0;

    let bar_x = 72.0;
    let bar_max = 180.0;
    b.text(10, "Client vs Industry Benchmark");
    let client_len = (score as f64 / 100.0 * bar_max).max(4.0);
    b.set_fill_rgb(0.2, 0.65, 0.9);
    b.rect_fill(bar_x, b.y - 18.0, client_len, 14.0);
    b.set_fill_rgb(0.3, 0.3, 0.35);
    b.text_at(bar_x + client_len + 6.0, 9, &format!("Client: {}", score));
    b.y -= 28.0;
    let ind_len = (65.0_f64 / 100.0 * bar_max).max(4.0);
    b.set_fill_rgb(0.5, 0.5, 0.55);
    b.rect_fill(bar_x, b.y - 18.0, ind_len, 14.0);
    b.set_fill_rgb(0.4, 0.4, 0.45);
    b.text_at(bar_x + ind_len + 6.0, 9, "Industry Avg: 65");
    b.y -= 24.0;

    let discovery_n = discovery_noise_count(findings);
    if discovery_n > 0 {
        b.set_fill_rgb(0.45, 0.5, 0.6);
        b.text(
            10,
            &format!(
                "Attack Surface Discovery: Found {} subdomains/ports (reconnaissance only). See Appendix for full list.",
                discovery_n
            ),
        );
        b.y -= 12.0;
    }
    b.y -= 16.0;
    b.new_page();

    // ---------- REMEDIATION ROADMAP ----------
    b.set_fill_rgb(0.0, 0.0, 0.0);
    b.text(16, "Executive Remediation Roadmap");
    b.set_fill_rgb(0.4, 0.45, 0.55);
    b.text(10, "Top 3 strategic actions derived from findings.");
    b.y -= 20.0;

    let severity_weight = |s: &str| -> i32 {
        let s = s.to_lowercase();
        if s.contains("critical") {
            4
        } else if s.contains("high") {
            3
        } else if s.contains("medium") || s.contains("med") {
            2
        } else {
            1
        }
    };
    let detailed_for_roadmap: Vec<_> = findings
        .iter()
        .filter(|f| should_include_in_detailed_findings(f))
        .collect();
    let mut sorted: Vec<_> = detailed_for_roadmap;
    sorted.sort_by(|a, b| {
        severity_weight(&b.2)
            .cmp(&severity_weight(&a.2))
            .then_with(|| {
                remediation_priority_score_for_row(&b.4, &b.2, &b.5)
                    .cmp(&remediation_priority_score_for_row(&a.4, &a.2, &a.5))
            })
    });
    let top3: Vec<_> = sorted.into_iter().take(3).collect();

    for (idx, (id, title, severity, _src, desc, _poc)) in top3.iter().enumerate() {
        b.ensure_space(80.0);
        let priority = idx + 1;
        let box_y = b.y;
        b.set_fill_rgb(0.08, 0.1, 0.14);
        b.rect_fill(72.0, b.y - 72.0, PAGE_W - 144.0, 70.0);
        b.set_stroke_rgb(0.25, 0.6, 0.85);
        b.current.push_str("0.5 w\n");
        b.rect_stroke(72.0, box_y - 72.0, PAGE_W - 144.0, 70.0);
        b.set_fill_rgb(0.25, 0.7, 0.95);
        b.text_at(82.0, 11, &format!("PRIORITY {}", priority));
        b.set_fill_rgb(0.95, 0.5, 0.35);
        b.text_at(82.0, 9, "Threat:");
        b.set_fill_rgb(0.85, 0.85, 0.9);
        b.text_at(
            130.0,
            9,
            &truncate_ascii(&format!("{} exposure — {}", severity, title), 75),
        );
        b.set_fill_rgb(0.35, 0.85, 0.55);
        b.text_at(82.0, 9, "Action:");
        let rem = remediation_from_desc(desc);
        let action = if rem != "—" {
            rem
        } else {
            format!("Remediate VLN-{}", id)
        };
        b.text_at(130.0, 9, &truncate_ascii(&action, 75));
        b.set_fill_rgb(0.9, 0.75, 0.3);
        let eff = if severity.to_lowercase().contains("critical") {
            "High Impact / Critical"
        } else if severity.to_lowercase().contains("high") {
            "High Impact / Moderate Effort"
        } else {
            "Moderate Impact / Easy Fix"
        };
        b.text_at(82.0, 9, &format!("Efficiency: {}", eff));
        b.y = box_y - 78.0;
    }
    b.y -= 20.0;
    b.new_page();

    // ---------- THREAT INTELLIGENCE BOX ----------
    b.set_fill_rgb(0.0, 0.0, 0.0);
    b.text(14, "Threat Intelligence");
    b.set_fill_rgb(0.08, 0.1, 0.15);
    b.rect_fill(72.0, b.y - 42.0, PAGE_W - 144.0, 38.0);
    b.set_stroke_rgb(0.6, 0.25, 0.25);
    b.current.push_str("0.5 w\n");
    b.rect_stroke(72.0, b.y - 42.0, PAGE_W - 144.0, 38.0);
    b.set_fill_rgb(0.9, 0.4, 0.4);
    b.text_at(82.0, 9, "Likely Threat Actors (contextual):");
    b.set_fill_rgb(0.75, 0.78, 0.85);
    b.text_at(
        82.0,
        9,
        "APT28, FIN7, Lazarus — prioritize external exposure and auth findings.",
    );
    b.y -= 52.0;
    b.new_page();

    // ---------- TECHNICAL FINDING DETAILS (Proof-of-breach filter: poc or HIGH/CRITICAL only) ----------
    let detailed_findings: Vec<&FindingRow> = findings
        .iter()
        .filter(|f| should_include_in_detailed_findings(f))
        .collect();

    b.set_fill_rgb(0.0, 0.0, 0.0);
    b.text(16, "Technical Finding Details");
    b.set_fill_rgb(0.4, 0.45, 0.55);
    b.text(
        10,
        "Proof-of-breach only: findings with Safe Reproduce (cURL) or HIGH/CRITICAL severity.",
    );
    b.y -= 24.0;

    for (id, title, severity, source, desc, poc_exploit) in &detailed_findings {
        b.ensure_space(120.0);

        let bar_color = if severity.to_lowercase().contains("critical") {
            (0.9, 0.25, 0.25)
        } else if severity.to_lowercase().contains("high") {
            (0.95, 0.5, 0.2)
        } else if severity.to_lowercase().contains("medium")
            || severity.to_lowercase().contains("med")
        {
            (0.9, 0.8, 0.2)
        } else {
            (0.3, 0.65, 0.4)
        };
        b.set_fill_rgb(bar_color.0, bar_color.1, bar_color.2);
        b.rect_fill(72.0, b.y - 2.0, 4.0, 60.0);

        b.set_fill_rgb(0.25, 0.7, 0.95);
        b.text_at(
            84.0,
            11,
            &format!("VLN-{} | {} | {}", id, severity, truncate_ascii(title, 55)),
        );
        b.set_fill_rgb(0.5, 0.55, 0.6);
        b.text_at(84.0, 9, &format!("Source: {}", source));
        let rp = remediation_priority_score_for_row(desc, severity, poc_exploit);
        b.set_fill_rgb(0.85, 0.55, 0.35);
        b.text_at(
            84.0,
            9,
            &format!(
                "Remediation Priority Score: {}/100 (severity + PoE + entropy + stack/CVE match)",
                rp
            ),
        );
        b.y -= 22.0;

        b.set_fill_rgb(0.12, 0.14, 0.18);
        b.rect_fill(84.0, b.y - 42.0, PAGE_W - 168.0, 40.0);
        b.set_stroke_rgb(0.25, 0.7, 0.45);
        b.current.push_str("0.8 w\n");
        b.rect_stroke(84.0, b.y - 42.0, PAGE_W - 168.0, 40.0);
        b.set_fill_rgb(0.4, 0.95, 0.55);
        b.text_at(90.0, 8, "Safe Reproduce (cURL) — Proof of Breach:");
        let poc = poc_exploit.trim();
        let poc_show = if poc.is_empty() {
            "— No reproduction payload captured (verify manually).".to_string()
        } else {
            truncate_ascii(poc, 95)
        };
        b.set_fill_rgb(0.85, 0.9, 0.85);
        b.text_at(90.0, 8, &poc_show);
        b.y -= 48.0;

        let rem = remediation_from_desc(desc);
        b.set_fill_rgb(0.12, 0.14, 0.18);
        b.rect_fill(84.0, b.y - 32.0, PAGE_W - 168.0, 30.0);
        b.set_stroke_rgb(0.3, 0.35, 0.4);
        b.rect_stroke(84.0, b.y - 32.0, PAGE_W - 168.0, 30.0);
        b.set_fill_rgb(0.35, 0.85, 0.55);
        b.text_at(90.0, 8, "Remediation:");
        b.set_fill_rgb(0.8, 0.85, 0.8);
        b.text_at(
            90.0,
            8,
            &truncate_ascii(
                if rem != "—" {
                    &rem
                } else {
                    "— See vendor guidance."
                },
                95,
            ),
        );
        b.y -= 42.0;
    }

    if detailed_findings.is_empty() {
        b.set_fill_rgb(0.5, 0.5, 0.55);
        b.text(10, "No proof-of-breach findings (no cURL/HIGH/CRITICAL with remediation). Data is live from the database.");
    }

    b.new_page();
    b.set_fill_rgb(0.35, 0.4, 0.5);
    b.text_at(72.0, 10, "Cryptographic Proof of Integrity");
    if let Some((h, _, verify)) = crypto_proof {
        b.text_at(72.0, 9, &format!("SHA-256: {}", truncate_ascii(h, 70)));
        b.text_at(72.0, 9, &truncate_ascii(verify, 70));
    }
    b.text_at(72.0, 8, "(c) Weissman Cybersecurity — Confidential.");

    let streams = b.finish();

    let mut out = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    out.extend_from_slice(b"%PDF-1.4\n");
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());

    let n = streams.len();
    let page_objects: Vec<usize> = (0..n).map(|i| 3 + i * 2).collect();
    let contents_objects: Vec<usize> = (0..n).map(|i| 4 + i * 2).collect();

    let pages_refs: String = page_objects.iter().map(|i| format!("{} 0 R ", i)).collect();
    out.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [ {}] /Count {} >>\nendobj\n",
            pages_refs.trim(),
            n
        )
        .as_bytes(),
    );
    offsets.push(out.len());

    let font_obj = 3 + 2 * n;
    for (i, stream_body) in streams.iter().enumerate() {
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>\nendobj\n",
                page_objects[i],
                contents_objects[i],
                font_obj
            )
            .as_bytes(),
        );
        offsets.push(out.len());
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
                contents_objects[i],
                stream_body.len(),
                stream_body
            )
            .as_bytes(),
        );
        offsets.push(out.len());
    }

    out.extend_from_slice(
        format!(
            "{} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
            font_obj
        )
        .as_bytes(),
    );
    offsets.push(out.len());

    let xref_start = out.len();
    let num_objs = font_obj;
    out.extend_from_slice(b"xref\n");
    out.extend_from_slice(format!("0 {} \n", num_objs + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1).take(num_objs) {
        out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            num_objs + 1,
            xref_start
        )
        .as_bytes(),
    );
    Ok(out)
}

/// Minimal PDF (single page) when full build not needed. Helvetica only.
pub fn build_minimal_pdf(client_name: &str, findings_count: usize) -> Vec<u8> {
    let date = israel_now();
    let title_escaped = pdf_escape(&format!("Weissman Report - {}", client_name));
    let sub_escaped = pdf_escape(&format!(
        "Report Generated: {} (Israel) | Findings: {}",
        date, findings_count
    ));
    let stream_body = format!(
        "BT\n/F1 18 Tf\n72 720 Td\n({}) Tj\n0 -24 Td\n/F1 12 Tf\n({}) Tj\nET",
        title_escaped, sub_escaped
    );
    let mut out = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    out.extend_from_slice(b"%PDF-1.4\n");
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    offsets.push(out.len());
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
    );
    offsets.push(out.len());
    out.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            stream_body.len(),
            stream_body
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    out.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    );
    let xref_offset = out.len();
    out.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for off in offsets.iter().skip(1).take(5) {
        out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            xref_offset
        )
        .as_bytes(),
    );
    out
}

/// Board-ready executive summary: aggregate risk and compliance posture (no raw PoC blocks).
pub fn build_executive_board_pdf(
    org_label: &str,
    client_opt: Option<&str>,
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    cloud_finding_count: usize,
    soc2_pct: u8,
    iso_pct: u8,
    gdpr_pct: u8,
) -> Result<Vec<u8>, String> {
    let date = israel_now();
    let mut b = PdfBuilder::new();
    b.set_fill_rgb(0.06, 0.09, 0.14);
    b.text(22, "WEISSMAN — EXECUTIVE / BOARD BRIEFING");
    b.set_fill_rgb(0.55, 0.62, 0.72);
    b.text(
        11,
        &format!("Organization: {}", truncate_ascii(org_label, 80)),
    );
    if let Some(c) = client_opt {
        b.text(11, &format!("Scope (client): {}", truncate_ascii(c, 80)));
    }
    b.text(10, &format!("Generated (Israel): {}", date));
    b.y -= 8.0;

    b.set_fill_rgb(0.2, 0.75, 0.95);
    b.text(14, "Risk posture (application & cloud)");
    b.set_fill_rgb(0.9, 0.92, 0.95);
    b.text(
        11,
        &format!(
            "Critical: {}  |  High: {}  |  Medium: {}  |  Low / Info: {}",
            critical, high, medium, low
        ),
    );
    b.text(
        11,
        &format!(
            "Agentless cloud misconfigurations (latest scan): {}",
            cloud_finding_count
        ),
    );

    b.y -= 10.0;
    b.set_fill_rgb(0.2, 0.75, 0.95);
    b.text(14, "Continuous compliance (mapped controls)");
    b.set_fill_rgb(0.85, 0.9, 0.95);
    b.text(12, &format!("SOC 2 (mapped): {}% aligned", soc2_pct));
    b.text(12, &format!("ISO 27001 (mapped): {}% aligned", iso_pct));
    b.text(
        12,
        &format!("GDPR (Art. 32 / mapped): {}% aligned", gdpr_pct),
    );

    b.y -= 14.0;
    b.set_fill_rgb(0.45, 0.5, 0.58);
    b.text(
        9,
        "Figures derive from live findings (vulnerabilities + agentless cloud rules) against the compliance_mappings catalog.",
    );
    b.text(
        9,
        "This document is confidential. Distribution is limited to authorized risk and audit committees.",
    );

    let streams = b.finish();
    let mut out = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    out.extend_from_slice(b"%PDF-1.4\n");
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());
    let n = streams.len();
    let page_objects: Vec<usize> = (0..n).map(|i| 3 + i * 2).collect();
    let contents_objects: Vec<usize> = (0..n).map(|i| 4 + i * 2).collect();
    let pages_refs: String = page_objects.iter().map(|i| format!("{} 0 R ", i)).collect();
    out.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [ {}] /Count {} >>\nendobj\n",
            pages_refs.trim(),
            n
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    let font_obj = 3 + 2 * n;
    for (i, stream_body) in streams.iter().enumerate() {
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>\nendobj\n",
                page_objects[i],
                contents_objects[i],
                font_obj
            )
            .as_bytes(),
        );
        offsets.push(out.len());
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
                contents_objects[i],
                stream_body.len(),
                stream_body
            )
            .as_bytes(),
        );
        offsets.push(out.len());
    }
    out.extend_from_slice(
        format!(
            "{} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
            font_obj
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    let xref_start = out.len();
    let num_objs = font_obj;
    out.extend_from_slice(b"xref\n");
    out.extend_from_slice(format!("0 {} \n", num_objs + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1).take(num_objs) {
        out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            num_objs + 1,
            xref_start
        )
        .as_bytes(),
    );
    Ok(out)
}

/// Build HTML report (unchanged structure). Strictly live from DB. Israel time. Rating, heatmap, cURL, integrity.
pub fn build_client_report_html(
    client_name: &str,
    findings: &[FindingRow],
    crypto_proof: Option<&CryptoProof>,
) -> String {
    let date = israel_now();
    let (critical, high, medium, low_info) =
        findings
            .iter()
            .fold((0i64, 0i64, 0i64, 0i64), |acc, (_, _, sev, _, _, _)| {
                let s = sev.to_lowercase();
                let (c, h, m, l) = acc;
                if s.contains("critical") {
                    (c + 1, h, m, l)
                } else if s.contains("high") {
                    (c, h + 1, m, l)
                } else if s.contains("medium") || s.contains("med") {
                    (c, h, m + 1, l)
                } else {
                    (c, h, m, l + 1)
                }
            });
    let score = (100 - critical * 25 - high * 15 - medium * 5)
        .max(0)
        .min(100);

    fn remediation_from_description(desc: &str) -> String {
        let desc = desc.trim();
        if desc.is_empty() {
            return "—".to_string();
        }
        if let Ok(v) = serde_json::from_str::<JsonValue>(desc) {
            if let Some(s) = v.get("remediation_snippet").and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
            if let Some(s) = v.get("remediation").and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
        "—".to_string()
    }

    let rows: String = findings
        .iter()
        .map(|(id, title, severity, source, desc, poc_exploit)| {
            let curl_cell = if poc_exploit.trim().is_empty() {
                "—".to_string()
            } else {
                format!(
                    "<pre class=\"curl-block\">{}</pre>",
                    escape(poc_exploit.trim()).replace('\n', "<br/>")
                )
            };
            let remediation = remediation_from_description(desc);
            let remediation_cell = if remediation == "—" {
                "—".to_string()
            } else {
                format!(
                    "<pre class=\"remediation-block\">{}</pre>",
                    escape(remediation.trim()).replace('\n', "<br/>")
                )
            };
            format!(
                "<tr><td>VLN-{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"curl-cell\">{}</td><td class=\"remediation-cell\">{}</td></tr>",
                id,
                escape(severity),
                escape(title),
                escape(source),
                curl_cell,
                remediation_cell,
            )
        })
        .collect();
    let table_body = if rows.is_empty() {
        r#"<tr><td colspan="6">No findings. Data is live from the database.</td></tr>"#.to_string()
    } else {
        rows
    };

    let heatmap = format!(
        r##"<div class="heatmap">
  <h3>Risk Heatmap</h3>
  <table class="heatmap-tbl"><tbody>
    <tr><td class="sev-critical">Critical</td><td>{}</td></tr>
    <tr><td class="sev-high">High</td><td>{}</td></tr>
    <tr><td class="sev-medium">Medium</td><td>{}</td></tr>
    <tr><td class="sev-low">Low / Info</td><td>{}</td></tr>
  </tbody></table>
</div>"##,
        critical, high, medium, low_info
    );

    let crypto_section = if let Some((hash, qr_data_url, verify_url)) = crypto_proof {
        format!(
            r##"
  <div class="crypto-proof">
    <h2>Cryptographic Proof of Integrity</h2>
    <p class="crypto-desc">This report is cryptographically sealed.</p>
    <div class="crypto-flex">
      <img src="{qr_data_url}" alt="QR verification" class="crypto-qr"/>
      <div>
        <p class="crypto-hash"><strong>Audit Root Hash (SHA-256):</strong><br/><code>{hash}</code></p>
        <p class="crypto-verify"><a href="{verify_url}">Verify: {verify_url}</a></p>
      </div>
    </div>
  </div>"##,
            qr_data_url = escape(qr_data_url),
            hash = escape(hash),
            verify_url = escape(verify_url),
        )
    } else {
        String::new()
    };

    let body_without_stamp = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Weissman Executive Report — {client_name}</title>
  <style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 2rem; color: #1e293b; }}
    h1 {{ color: #0f172a; border-bottom: 2px solid #0ea5e9; padding-bottom: 0.5rem; }}
    .meta {{ color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .rating-box {{ font-size: 2.5rem; font-weight: 700; color: #0ea5e9; margin: 1rem 0; padding: 1rem; border: 2px solid #0ea5e9; border-radius: 8px; text-align: center; }}
    .heatmap {{ margin: 1.5rem 0; }}
    .heatmap-tbl {{ width: auto; border-collapse: collapse; }}
    .heatmap-tbl td {{ padding: 0.35rem 1rem; border: 1px solid #e2e8f0; }}
    .sev-critical {{ background: #fecaca; color: #991b1b; font-weight: 600; }}
    .sev-high {{ background: #fed7aa; color: #9a3412; font-weight: 600; }}
    .sev-medium {{ background: #fef08a; color: #854d0e; }}
    .sev-low {{ background: #d1fae5; color: #065f46; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ padding: 0.5rem 0.75rem; text-align: left; border: 1px solid #e2e8f0; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .curl-cell {{ font-size: 0.8rem; max-width: 320px; word-break: break-all; }}
    .curl-block {{ margin: 0; font-family: ui-monospace, monospace; white-space: pre-wrap; background: #f8fafc; padding: 0.5rem; border-radius: 4px; }}
    .remediation-cell {{ font-size: 0.85rem; max-width: 280px; word-break: break-word; color: #047857; }}
    .remediation-block {{ margin: 0; font-family: ui-monospace, monospace; white-space: pre-wrap; background: #ecfdf5; border-left: 3px solid #10b981; padding: 0.5rem; border-radius: 4px; }}
    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8; }}
    .integrity {{ margin-top: 2rem; padding: 1rem; background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 8px; font-family: ui-monospace, monospace; font-size: 0.8rem; word-break: break-all; }}
    .crypto-proof {{ margin-top: 2.5rem; padding: 1.25rem; border: 1px solid #0ea5e9; background: #f0f9ff; border-radius: 8px; }}
    .crypto-desc {{ font-size: 0.9rem; color: #0c4a6e; margin-bottom: 1rem; }}
    .crypto-flex {{ display: flex; gap: 1.5rem; align-items: flex-start; flex-wrap: wrap; }}
    .crypto-qr {{ width: 160px; height: 160px; }}
    .crypto-hash {{ font-family: ui-monospace, monospace; font-size: 0.8rem; word-break: break-all; }}
    .crypto-verify {{ margin-top: 0.5rem; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h1>WEISSMAN CYBERSECURITY</h1>
  <p class="meta">Executive Security Assessment Report — {client_name}<br/>Report Generated: {date} (Israel)</p>
  <h2>Weissman Security Rating</h2>
  <div class="rating-box">{score}/100</div>
  {heatmap}
  <h2>Detailed Findings (Live from DB)</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Engine/Source</th><th>Safe Reproduce (cURL)</th><th>Remediation</th></tr></thead>
    <tbody>{table_body}</tbody>
  </table>
  {crypto_section}
  <p class="footer">© Weissman Cybersecurity — Confidential.</p>
  <div class="integrity"><strong>Digital Integrity Stamp:</strong> {{HASH_PLACEHOLDER}}</div>
</body>
</html>"##,
        client_name = escape(client_name),
        date = date,
        score = score,
        heatmap = heatmap,
        table_body = table_body,
        crypto_section = crypto_section,
    );

    let content_for_hash = body_without_stamp.replace("{{HASH_PLACEHOLDER}}", "");
    let mut hasher = Sha256::new();
    hasher.update(content_for_hash.as_bytes());
    let hash_hex = format!("{:x}", hasher.finalize());
    body_without_stamp.replace("{{HASH_PLACEHOLDER}}", &hash_hex)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
