//! RFC 4180 CSV with spreadsheet-formula injection protection and a UTF-8 BOM so Excel
//! opens Hebrew columns correctly.

/// Prefix that makes Excel treat the file as UTF-8.
pub const UTF8_BOM: &str = "\u{FEFF}";

/// Escape one cell: formula-injection prefix for leading `= + - @` (or tab/CR), then RFC 4180 quoting.
#[must_use]
pub fn escape_cell(v: &str) -> String {
    let mut s = v.replace(['\r', '\n'], " ");
    if s.starts_with(['=', '+', '-', '@', '\t']) {
        s.insert(0, '\'');
    }
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Join `cells` into one CSV record.
#[must_use]
pub fn record<I, S>(cells: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::new();
    for (i, cell) in cells.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&escape_cell(cell.as_ref()));
    }
    out.push('\n');
    out
}

/// Build a complete CSV document: BOM + header + rows.
#[must_use]
pub fn document(header: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut out = String::from(UTF8_BOM);
    out.push_str(&record(header.iter().copied()));
    for row in rows {
        out.push_str(&record(row));
    }
    out
}

/// Attachment headers for a CSV download.
#[must_use]
pub fn content_type() -> &'static str {
    "text/csv; charset=utf-8"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_commas_and_doubles_embedded_quotes() {
        assert_eq!(escape_cell(r#"a"b,c"#), r#""a""b,c""#);
    }

    #[test]
    fn prefixes_formula_injection_characters() {
        for lead in ['=', '+', '-', '@'] {
            let out = escape_cell(&format!("{lead}1+1"));
            assert!(out.starts_with("\"'"), "{out}");
        }
    }

    #[test]
    fn document_starts_with_utf8_bom() {
        let csv = document(&["a"], [vec!["b".into()]]);
        assert!(csv.starts_with(UTF8_BOM));
        assert!(csv.contains("\"a\""));
        assert!(csv.contains("\"b\""));
    }

    #[test]
    fn newlines_inside_cells_are_flattened() {
        assert_eq!(escape_cell("a\nb\rc"), "\"a b c\"");
    }
}
