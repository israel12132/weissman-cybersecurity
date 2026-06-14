//! Sigma-style detection-as-code over structured events.
//!
//! Detections are data, not code: a [`SigmaRule`] declares named **selections** (field predicates)
//! and a boolean **condition** expression over them (`sel and not filter`, `1 of them`,
//! `all of them`, parentheses). [`evaluate`] runs rules over a stream of JSON events. This is the
//! "detection-as-code / Sigma" capability the platform lacked.
//!
//! Pure and fully unit-tested — including the condition-expression parser.

use serde::Serialize;

/// String comparison operator for a field predicate (all case-insensitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Op {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

/// A single field predicate. Matches when the event's `field` satisfies `op` against ANY `value`.
#[derive(Debug, Clone, Serialize)]
pub struct FieldMatch {
    pub field: String,
    pub op: Op,
    pub values: Vec<String>,
}

impl FieldMatch {
    pub fn new(field: &str, op: Op, values: &[&str]) -> Self {
        Self {
            field: field.to_string(),
            op,
            values: values.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn matches(&self, event: &serde_json::Value) -> bool {
        let Some(actual) = get_field(event, &self.field) else {
            return false;
        };
        let a = actual.to_ascii_lowercase();
        self.values.iter().any(|v| {
            let v = v.to_ascii_lowercase();
            match self.op {
                Op::Equals => a == v,
                Op::Contains => a.contains(&v),
                Op::StartsWith => a.starts_with(&v),
                Op::EndsWith => a.ends_with(&v),
            }
        })
    }
}

/// A named selection: ALL of its field predicates must match (logical AND across fields).
#[derive(Debug, Clone, Serialize)]
pub struct Selection {
    pub name: String,
    pub fields: Vec<FieldMatch>,
}

impl Selection {
    pub fn new(name: &str, fields: Vec<FieldMatch>) -> Self {
        Self {
            name: name.to_string(),
            fields,
        }
    }
    fn matches(&self, event: &serde_json::Value) -> bool {
        !self.fields.is_empty() && self.fields.iter().all(|f| f.matches(event))
    }
}

/// A detection rule: selections + a boolean condition expression over selection names.
#[derive(Debug, Clone, Serialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub level: String,
    pub selections: Vec<Selection>,
    pub condition: String,
}

/// A fired detection for a specific event index.
#[derive(Debug, Clone, Serialize)]
pub struct SigmaHit {
    pub rule_id: String,
    pub title: String,
    pub level: String,
    pub event_index: usize,
}

fn get_field(event: &serde_json::Value, field: &str) -> Option<String> {
    match event.get(field) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

impl SigmaRule {
    /// Evaluate the rule against a single event.
    pub fn matches(&self, event: &serde_json::Value) -> bool {
        let mut sel_results = std::collections::HashMap::new();
        let mut any = false;
        let mut all = !self.selections.is_empty();
        for s in &self.selections {
            let m = s.matches(event);
            any |= m;
            all &= m;
            sel_results.insert(s.name.clone(), m);
        }
        eval_condition(&self.condition, &sel_results, all, any)
    }
}

/// Evaluate rules over a stream of events; returns one hit per (rule, matching event).
pub fn evaluate(rules: &[SigmaRule], events: &[serde_json::Value]) -> Vec<SigmaHit> {
    let mut hits = Vec::new();
    for rule in rules {
        for (i, ev) in events.iter().enumerate() {
            if rule.matches(ev) {
                hits.push(SigmaHit {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    level: rule.level.clone(),
                    event_index: i,
                });
            }
        }
    }
    hits
}

// ── Condition expression parser ────────────────────────────────────────────────
//
// Grammar:
//   expr    := or_expr
//   or_expr := and_expr ( "or"  and_expr )*
//   and_expr:= not_expr ( "and" not_expr )*
//   not_expr:= "not" not_expr | atom
//   atom    := "(" expr ")" | "__ALLOF__" | "__ANYOF__" | NAME

fn tokenize_condition(condition: &str) -> Vec<String> {
    // Normalize the multi-word quantifier phrases into single tokens first.
    let mut s = condition.to_string();
    for (phrase, tok) in [
        ("all of them", " __ALLOF__ "),
        ("1 of them", " __ANYOF__ "),
        ("any of them", " __ANYOF__ "),
    ] {
        // case-insensitive phrase replace
        let mut out = String::new();
        let lower = s.to_ascii_lowercase();
        let mut idx = 0;
        while let Some(pos) = lower[idx..].find(phrase) {
            let start = idx + pos;
            out.push_str(&s[idx..start]);
            out.push_str(tok);
            idx = start + phrase.len();
        }
        out.push_str(&s[idx..]);
        s = out;
    }
    // Pad parentheses so split_whitespace separates them.
    s = s.replace('(', " ( ").replace(')', " ) ");
    s.split_whitespace().map(str::to_string).collect()
}

struct CondParser<'a> {
    tokens: Vec<String>,
    pos: usize,
    sel: &'a std::collections::HashMap<String, bool>,
    all_true: bool,
    any_true: bool,
}

impl<'a> CondParser<'a> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(String::as_str)
    }
    fn is_kw(&self, kw: &str) -> bool {
        self.peek().is_some_and(|t| t.eq_ignore_ascii_case(kw))
    }
    fn bump(&mut self) -> Option<String> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_expr(&mut self) -> Option<bool> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<bool> {
        let mut v = self.parse_and()?;
        while self.is_kw("or") {
            self.bump();
            let r = self.parse_and()?;
            v = v || r;
        }
        Some(v)
    }

    fn parse_and(&mut self) -> Option<bool> {
        let mut v = self.parse_not()?;
        while self.is_kw("and") {
            self.bump();
            let r = self.parse_not()?;
            v = v && r;
        }
        Some(v)
    }

    fn parse_not(&mut self) -> Option<bool> {
        if self.is_kw("not") {
            self.bump();
            let v = self.parse_not()?;
            return Some(!v);
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Option<bool> {
        let tok = self.bump()?;
        if tok == "(" {
            let v = self.parse_expr()?;
            // consume ")"
            if self.peek() == Some(")") {
                self.bump();
                Some(v)
            } else {
                None
            }
        } else if tok == "__ALLOF__" {
            Some(self.all_true)
        } else if tok == "__ANYOF__" {
            Some(self.any_true)
        } else {
            // selection name (unknown ⇒ false)
            Some(self.sel.get(&tok).copied().unwrap_or(false))
        }
    }
}

fn eval_condition(
    condition: &str,
    sel: &std::collections::HashMap<String, bool>,
    all_true: bool,
    any_true: bool,
) -> bool {
    let tokens = tokenize_condition(condition);
    if tokens.is_empty() {
        return false;
    }
    let mut p = CondParser {
        tokens,
        pos: 0,
        sel,
        all_true,
        any_true,
    };
    match p.parse_expr() {
        Some(v) if p.pos == p.tokens.len() => v,
        _ => false, // parse error / trailing tokens ⇒ do not fire
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(pairs: &[(&str, &str)]) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for (k, v) in pairs {
            m.insert(
                (*k).to_string(),
                serde_json::Value::String((*v).to_string()),
            );
        }
        serde_json::Value::Object(m)
    }

    #[test]
    fn field_ops() {
        let e = ev(&[("path", "/admin/login"), ("ua", "sqlmap/1.5")]);
        assert!(FieldMatch::new("path", Op::Contains, &["admin"]).matches(&e));
        assert!(FieldMatch::new("ua", Op::StartsWith, &["sqlmap"]).matches(&e));
        assert!(FieldMatch::new("path", Op::EndsWith, &["login"]).matches(&e));
        assert!(!FieldMatch::new("path", Op::Equals, &["/admin"]).matches(&e));
        assert!(FieldMatch::new("path", Op::Equals, &["/ADMIN/login"]).matches(&e));
        // case-insensitive
    }

    #[test]
    fn selection_is_and_across_fields() {
        let sel = Selection::new(
            "s",
            vec![
                FieldMatch::new("a", Op::Equals, &["1"]),
                FieldMatch::new("b", Op::Equals, &["2"]),
            ],
        );
        assert!(sel.matches(&ev(&[("a", "1"), ("b", "2")])));
        assert!(!sel.matches(&ev(&[("a", "1"), ("b", "3")])));
    }

    fn rule(condition: &str) -> SigmaRule {
        SigmaRule {
            id: "r".into(),
            title: "t".into(),
            level: "high".into(),
            selections: vec![
                Selection::new("sel", vec![FieldMatch::new("evt", Op::Equals, &["attack"])]),
                Selection::new(
                    "filter",
                    vec![FieldMatch::new("src", Op::Equals, &["trusted"])],
                ),
            ],
            condition: condition.into(),
        }
    }

    #[test]
    fn condition_and_not() {
        let r = rule("sel and not filter");
        assert!(r.matches(&ev(&[("evt", "attack"), ("src", "internet")])));
        assert!(!r.matches(&ev(&[("evt", "attack"), ("src", "trusted")]))); // filtered out
        assert!(!r.matches(&ev(&[("evt", "benign"), ("src", "internet")])));
    }

    #[test]
    fn condition_quantifiers() {
        let any = rule("1 of them");
        assert!(any.matches(&ev(&[("evt", "attack"), ("src", "x")]))); // sel true
        assert!(any.matches(&ev(&[("evt", "x"), ("src", "trusted")]))); // filter true
        assert!(!any.matches(&ev(&[("evt", "x"), ("src", "x")])));

        let all = rule("all of them");
        assert!(all.matches(&ev(&[("evt", "attack"), ("src", "trusted")])));
        assert!(!all.matches(&ev(&[("evt", "attack"), ("src", "x")])));
    }

    #[test]
    fn condition_parens_precedence() {
        let r = rule("(sel or filter) and not filter");
        // sel true, filter false → (true) and not false = true
        assert!(r.matches(&ev(&[("evt", "attack"), ("src", "x")])));
        // sel false, filter true → (true) and not true = false
        assert!(!r.matches(&ev(&[("evt", "x"), ("src", "trusted")])));
    }

    #[test]
    fn malformed_condition_does_not_fire() {
        let r = rule("sel and"); // dangling operator
        assert!(!r.matches(&ev(&[("evt", "attack"), ("src", "x")])));
    }

    #[test]
    fn evaluate_stream_reports_indices() {
        let r = rule("sel and not filter");
        let events = vec![
            ev(&[("evt", "attack"), ("src", "internet")]), // match
            ev(&[("evt", "benign"), ("src", "internet")]), // no
            ev(&[("evt", "attack"), ("src", "internet")]), // match
        ];
        let hits = evaluate(&[r], &events);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].event_index, 0);
        assert_eq!(hits[1].event_index, 2);
    }
}
