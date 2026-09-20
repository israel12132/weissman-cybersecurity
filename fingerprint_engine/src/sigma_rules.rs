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

// ── Live host-event integration ─────────────────────────────────────────────────
//
// The evaluator above is pure. This section is the smallest real wiring of it to the endpoint
// agent's host telemetry: an embedded high-signal ruleset, a normalizer that maps a raw agent
// finding onto canonical Sigma field names, and helpers that turn each rule hit into a
// persistable finding envelope identical in shape to the agent's own host findings — so the
// existing `store_finding_for_task` / `findings_persist` path stores them with no special-casing.

/// Engine label under which Sigma matches persist (mirrors agent `type`/engine strings).
pub const SIGMA_ENGINE: &str = "sigma_detection";

pub const RULE_WORLD_WRITABLE_EXEC: &str = "weissman_proc_world_writable_exec";
pub const RULE_WEB_SHELL_SPAWN: &str = "weissman_web_server_shell_spawn";
pub const RULE_ENCODED_POWERSHELL: &str = "weissman_encoded_powershell";
pub const RULE_LOLBIN_EXEC: &str = "weissman_lolbin_execution";

/// The embedded default ruleset. Small, curated, high-signal MITRE detections that fire on the
/// host telemetry endpoint agents already emit (process inventory / DLL-hijack, CHRONOS shell
/// spawns) plus process-spawn command lines the fleet will report. There is no external Sigma
/// ruleset store in the schema, so this is the ruleset source until one is added.
pub fn default_ruleset() -> Vec<SigmaRule> {
    vec![
        SigmaRule {
            id: RULE_WORLD_WRITABLE_EXEC.into(),
            title: "Process executing from a world-writable / temp directory".into(),
            level: "high".into(),
            selections: vec![Selection::new(
                "selection",
                vec![FieldMatch::new(
                    "image",
                    Op::Contains,
                    &[
                        "\\appdata\\local\\temp\\",
                        "\\temp\\",
                        "/tmp/",
                        "/var/tmp/",
                        "/dev/shm/",
                    ],
                )],
            )],
            condition: "selection".into(),
        },
        SigmaRule {
            id: RULE_WEB_SHELL_SPAWN.into(),
            title: "Command shell spawned by a web/server process".into(),
            level: "critical".into(),
            selections: vec![
                Selection::new(
                    "parent_shell",
                    vec![
                        FieldMatch::new(
                            "parent_image",
                            Op::Contains,
                            &["nginx", "apache", "httpd", "w3wp", "tomcat", "node"],
                        ),
                        FieldMatch::new(
                            "process",
                            Op::EndsWith,
                            &[
                                "sh",
                                "bash",
                                "dash",
                                "zsh",
                                "cmd",
                                "cmd.exe",
                                "powershell",
                                "powershell.exe",
                                "pwsh",
                            ],
                        ),
                    ],
                ),
                Selection::new(
                    "chronos_hint",
                    vec![FieldMatch::new(
                        "syscall_hint",
                        Op::Contains,
                        &["spawned shell child"],
                    )],
                ),
            ],
            condition: "parent_shell or chronos_hint".into(),
        },
        SigmaRule {
            id: RULE_ENCODED_POWERSHELL.into(),
            title: "Encoded / obfuscated PowerShell command line".into(),
            level: "high".into(),
            selections: vec![Selection::new(
                "selection",
                vec![FieldMatch::new(
                    "commandline",
                    Op::Contains,
                    &[
                        "-enc ",
                        "-encodedcommand",
                        "frombase64string",
                        "invoke-expression",
                        "iex(",
                        "downloadstring",
                    ],
                )],
            )],
            condition: "selection".into(),
        },
        SigmaRule {
            id: RULE_LOLBIN_EXEC.into(),
            title: "Living-off-the-land binary execution".into(),
            level: "medium".into(),
            selections: vec![Selection::new(
                "selection",
                vec![FieldMatch::new(
                    "image",
                    Op::EndsWith,
                    &[
                        "\\certutil.exe",
                        "\\mshta.exe",
                        "\\regsvr32.exe",
                        "\\rundll32.exe",
                        "\\bitsadmin.exe",
                        "\\wmic.exe",
                        "/certutil",
                        "/mshta",
                    ],
                )],
            )],
            condition: "selection".into(),
        },
    ]
}

/// MITRE ATT&CK technique for an embedded rule id. The `SigmaRule` struct carries no MITRE field
/// (kept stable so existing constructors/tests compile), so the mapping lives here.
fn rule_mitre(rule_id: &str) -> &'static str {
    match rule_id {
        RULE_WORLD_WRITABLE_EXEC => "T1574.001",
        RULE_WEB_SHELL_SPAWN => "T1059",
        RULE_ENCODED_POWERSHELL => "T1059.001",
        RULE_LOLBIN_EXEC => "T1218",
        _ => "",
    }
}

/// First non-empty top-level string value among `keys`.
fn first_str<'a>(finding: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(s) = finding.get(*k).and_then(serde_json::Value::as_str) {
            if !s.trim().is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Normalize a raw endpoint-agent host finding into a flat Sigma event. Every top-level scalar is
/// carried through under its native key, then canonical aliases (`image`, `process`,
/// `commandline`, `parent_image`, `engine`) are added so one ruleset works across engines
/// regardless of each detection's native key spelling.
pub fn event_from_agent_finding(engine: &str, finding: &serde_json::Value) -> serde_json::Value {
    let mut ev = serde_json::Map::new();
    if let Some(obj) = finding.as_object() {
        for (k, v) in obj {
            if matches!(
                v,
                serde_json::Value::String(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::Bool(_)
            ) {
                ev.insert(k.clone(), v.clone());
            }
        }
    }
    let engine_name = if engine.trim().is_empty() {
        first_str(finding, &["type", "engine", "engine_id"]).unwrap_or("")
    } else {
        engine
    };
    ev.insert("engine".into(), serde_json::json!(engine_name));
    if let Some(v) = first_str(finding, &["image", "exe", "binary", "executable_path"]) {
        ev.insert("image".into(), serde_json::json!(v));
    }
    if let Some(v) = first_str(finding, &["process", "process_name", "name"]) {
        ev.insert("process".into(), serde_json::json!(v));
    }
    if let Some(v) = first_str(
        finding,
        &["commandline", "command_line", "cmd", "command", "args"],
    ) {
        ev.insert("commandline".into(), serde_json::json!(v));
    }
    if let Some(v) = first_str(
        finding,
        &[
            "parent_image",
            "parent_exe",
            "parent_process",
            "parent_name",
        ],
    ) {
        ev.insert("parent_image".into(), serde_json::json!(v));
    }
    serde_json::Value::Object(ev)
}

/// Compact one-line evidence string of the canonical fields present on a normalized event.
fn compact_evidence(event: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    for k in ["engine", "process", "image", "parent_image", "commandline"] {
        if let Some(s) = event.get(k).and_then(serde_json::Value::as_str) {
            if !s.trim().is_empty() {
                parts.push(format!("{k}={s}"));
            }
        }
    }
    if parts.is_empty() {
        "no canonical fields".to_string()
    } else {
        parts.join(" ")
    }
}

/// Turn one rule hit into a persistable finding envelope mirroring the agent host-finding shape
/// (`type`/`title`/`severity`/`mitre_attack`/`description`/`source`), plus Sigma provenance and
/// the matched event as evidence. The non-empty `description` also satisfies the persistence
/// evidence gate for actionable severities.
fn hit_to_finding(hit: &SigmaHit, event: &serde_json::Value) -> serde_json::Value {
    let mitre = rule_mitre(&hit.rule_id);
    let description = format!(
        "Sigma rule '{}' ({}) matched a host event: {}",
        hit.title,
        hit.rule_id,
        compact_evidence(event)
    );
    serde_json::json!({
        "type": SIGMA_ENGINE,
        "title": hit.title,
        "severity": hit.level,
        "mitre_attack": mitre,
        "description": description,
        "source": "agent",
        "detector": "sigma",
        "rule_id": hit.rule_id,
        "sigma_level": hit.level,
        "matched_event": event.clone(),
    })
}

/// Evaluate the embedded default ruleset against one already-normalized host event and return a
/// persistable finding per rule that fires.
pub fn detect_event(event: &serde_json::Value) -> Vec<serde_json::Value> {
    let rules = default_ruleset();
    evaluate(&rules, std::slice::from_ref(event))
        .iter()
        .map(|hit| hit_to_finding(hit, event))
        .collect()
}

/// Normalize a raw endpoint-agent host finding and evaluate the embedded default ruleset against
/// it, returning a persistable finding per rule hit. This is the entry point the WebSocket
/// ingest handler calls for every incoming agent finding.
pub fn detect_agent_finding(engine: &str, finding: &serde_json::Value) -> Vec<serde_json::Value> {
    let event = event_from_agent_finding(engine, finding);
    detect_event(&event)
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

    // ── Live host-event integration ──

    #[test]
    fn default_ruleset_is_wellformed_and_mapped() {
        let rules = default_ruleset();
        assert!(rules.len() >= 4);
        for r in &rules {
            assert!(!r.selections.is_empty(), "rule {} has no selections", r.id);
            assert!(
                !rule_mitre(&r.id).is_empty(),
                "rule {} has no MITRE mapping",
                r.id
            );
        }
    }

    #[test]
    fn encoded_powershell_event_yields_finding() {
        // A realistic process-spawn event with an encoded PowerShell command line.
        let event = serde_json::json!({
            "process": "powershell.exe",
            "commandline": "powershell -NoProfile -EncodedCommand SQBFAFgAKAAuAC4A",
        });
        let findings = detect_event(&event);
        assert_eq!(findings.len(), 1, "expected exactly one Sigma hit");
        let f = &findings[0];
        assert_eq!(f["type"], SIGMA_ENGINE);
        assert_eq!(f["mitre_attack"], "T1059.001");
        assert_eq!(f["severity"], "high");
        assert_eq!(f["rule_id"], RULE_ENCODED_POWERSHELL);
        assert!(!f["title"].as_str().unwrap().is_empty());
        // Non-empty description => passes the persistence evidence gate at actionable severity.
        assert!(f["description"]
            .as_str()
            .unwrap()
            .contains("EncodedCommand"));

        // A benign command line for the same process does not fire.
        let benign = serde_json::json!({
            "process": "powershell.exe",
            "commandline": "Get-Process",
        });
        assert!(detect_event(&benign).is_empty());
    }

    #[test]
    fn agent_finding_temp_dir_execution_maps_and_fires() {
        // Mirrors the agent DLL-hijack finding shape: an executable under a world-writable dir,
        // exposed under the native `exe` key which the normalizer maps to canonical `image`.
        let finding = serde_json::json!({
            "type": "dll_hijacking_engine",
            "title": "Process running from user-writable directory: evil",
            "severity": "medium",
            "description": "PID 42 (evil) is executing from '/tmp/evil'.",
            "exe": "/tmp/evil",
            "pid": 42,
        });
        let event = event_from_agent_finding("dll_hijacking_engine", &finding);
        assert_eq!(event["image"], "/tmp/evil");
        assert_eq!(event["engine"], "dll_hijacking_engine");

        let findings = detect_agent_finding("dll_hijacking_engine", &finding);
        assert!(
            findings
                .iter()
                .any(|f| f["mitre_attack"] == "T1574.001"
                    && f["rule_id"] == RULE_WORLD_WRITABLE_EXEC),
            "expected the world-writable-exec rule to fire on a /tmp/ image"
        );
    }

    #[test]
    fn chronos_web_shell_spawn_hint_fires_critical() {
        // CHRONOS emits `syscall_hint` describing a shell spawned from a web-server parent.
        let finding = serde_json::json!({
            "type": "chronos",
            "title": "CHRONOS freeze",
            "severity": "critical",
            "description": "shell spawn from web server parent",
            "process_name": "bash",
            "syscall_hint": "execve — web parent spawned shell child",
        });
        let findings = detect_agent_finding("chronos", &finding);
        assert!(
            findings
                .iter()
                .any(|f| f["rule_id"] == RULE_WEB_SHELL_SPAWN && f["severity"] == "critical"),
            "expected the web-server shell-spawn rule to fire on the CHRONOS hint"
        );
    }

    #[test]
    fn benign_process_inventory_finding_does_not_fire() {
        // A plain process-inventory finding (no temp path, no shell, no encoded cmd) must not fire.
        let finding = serde_json::json!({
            "type": "process_inventory",
            "title": "Process inventory: 120 processes / 60 unique images",
            "severity": "info",
            "description": "Agent enumerated every visible process.",
            "process_count": 120,
        });
        assert!(detect_agent_finding("process_inventory", &finding).is_empty());
    }
}
