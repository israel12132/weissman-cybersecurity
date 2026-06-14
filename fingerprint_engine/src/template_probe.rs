//! Data-driven n-day detection engine (Nuclei-style).
//!
//! A [`Template`] declares an HTTP request and a set of [`Matcher`]s; the engine executes the
//! request and emits a finding only when the matcher condition holds against the live response.
//! Templates are plain data (JSON-serializable), so n-day / exposure coverage grows by **shipping
//! templates, not code** — the missing piece for "engine depth + continuous CVE coverage".
//!
//! Matcher evaluation is pure and exhaustively unit-tested; request execution is real HTTP. No
//! finding is produced without an observed match.

use crate::engine_result::EngineResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Which part of the response a word matcher inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    Body,
    Headers,
    All,
}

impl Default for Part {
    fn default() -> Self {
        Part::Body
    }
}

/// How multiple words / matchers combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchLogic {
    And,
    Or,
}

impl Default for MatchLogic {
    fn default() -> Self {
        MatchLogic::And
    }
}

/// A single matcher: either a status-code match or a word (substring) match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    /// `"status"` or `"word"`.
    #[serde(rename = "type")]
    pub matcher_type: String,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub part: Part,
    #[serde(default)]
    pub condition: MatchLogic,
    #[serde(default)]
    pub negative: bool,
}

/// A snapshot of the response a matcher evaluates against.
#[derive(Debug, Clone)]
pub struct HttpResponseView {
    pub status: u16,
    pub headers: String,
    pub body: String,
}

impl HttpResponseView {
    fn part_text(&self, part: Part) -> std::borrow::Cow<'_, str> {
        match part {
            Part::Body => std::borrow::Cow::Borrowed(&self.body),
            Part::Headers => std::borrow::Cow::Borrowed(&self.headers),
            Part::All => std::borrow::Cow::Owned(format!("{}\n{}", self.headers, self.body)),
        }
    }
}

impl Matcher {
    /// Pure evaluation of this matcher against a response.
    pub fn matches(&self, resp: &HttpResponseView) -> bool {
        let raw = match self.matcher_type.as_str() {
            "status" => self.status.contains(&resp.status),
            "word" => {
                if self.words.is_empty() {
                    false
                } else {
                    let hay = resp.part_text(self.part);
                    let hay_l = hay.to_ascii_lowercase();
                    match self.condition {
                        MatchLogic::And => self
                            .words
                            .iter()
                            .all(|w| hay_l.contains(&w.to_ascii_lowercase())),
                        MatchLogic::Or => self
                            .words
                            .iter()
                            .any(|w| hay_l.contains(&w.to_ascii_lowercase())),
                    }
                }
            }
            _ => false,
        };
        if self.negative {
            !raw
        } else {
            raw
        }
    }
}

/// A detection template: a request plus matchers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub severity: String,
    #[serde(default)]
    pub mitre: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub matchers_condition: MatchLogic,
}

fn default_method() -> String {
    "GET".to_string()
}

impl Template {
    /// Pure: does this template's matcher set hold for the given response?
    pub fn evaluate(&self, resp: &HttpResponseView) -> bool {
        if self.matchers.is_empty() {
            return false;
        }
        match self.matchers_condition {
            MatchLogic::And => self.matchers.iter().all(|m| m.matches(resp)),
            MatchLogic::Or => self.matchers.iter().any(|m| m.matches(resp)),
        }
    }

    fn to_finding(&self, url: &str, status: u16) -> serde_json::Value {
        serde_json::json!({
            "type": "template_probe",
            "template_id": self.id,
            "title": self.name,
            "severity": self.severity,
            "mitre_attack": self.mitre,
            "value": url,
            "http_status": status,
            "description": format!(
                "n-day template '{}' matched on {} (HTTP {}).",
                self.id, url, status
            ),
        })
    }
}

fn join_url(base: &str, path: &str) -> String {
    let b = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{b}{path}")
    } else {
        format!("{b}/{path}")
    }
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

async fn fetch(client: &reqwest::Client, base: &str, t: &Template) -> Option<HttpResponseView> {
    let url = join_url(base, &t.path);
    let method = reqwest::Method::from_bytes(t.method.to_ascii_uppercase().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, &url);
    for (k, v) in &t.headers {
        req = req.header(k, v);
    }
    if let Some(b) = &t.body {
        req = req.body(b.clone());
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let mut headers = String::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.push_str(k.as_str());
            headers.push_str(": ");
            headers.push_str(s);
            headers.push('\n');
        }
    }
    let body = resp.text().await.unwrap_or_default();
    Some(HttpResponseView {
        status,
        headers,
        body,
    })
}

/// Execute a set of templates against a target. Real HTTP; one finding per matched template.
pub async fn run_templates_result(target: &str, templates: &[Template]) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResult::error(format!("client build: {e}")),
    };

    let mut findings = Vec::new();
    for t in templates {
        if let Some(resp) = fetch(&client, &base, t).await {
            if t.evaluate(&resp) {
                findings.push(t.to_finding(&join_url(&base, &t.path), resp.status));
            }
        }
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("template_probe: {n} template match(es) on {base}"),
    )
}

/// Execute the built-in exposure template pack.
pub async fn run_builtin_templates_result(target: &str) -> EngineResult {
    run_templates_result(target, &builtin_templates()).await
}

/// Parse templates from a JSON array (the "ship templates as data" path).
pub fn parse_templates(json: &str) -> Result<Vec<Template>, String> {
    serde_json::from_str::<Vec<Template>>(json).map_err(|e| e.to_string())
}

/// A small built-in pack of real exposure / misconfig n-day checks.
pub fn builtin_templates() -> Vec<Template> {
    vec![
        Template {
            id: "exposed-git-config".into(),
            name: "Exposed .git/config".into(),
            severity: "high".into(),
            mitre: "T1592".into(),
            method: "GET".into(),
            path: "/.git/config".into(),
            headers: vec![],
            body: None,
            matchers: vec![
                Matcher {
                    matcher_type: "status".into(),
                    status: vec![200],
                    words: vec![],
                    part: Part::Body,
                    condition: MatchLogic::Or,
                    negative: false,
                },
                Matcher {
                    matcher_type: "word".into(),
                    status: vec![],
                    words: vec!["[core]".into(), "repositoryformatversion".into()],
                    part: Part::Body,
                    condition: MatchLogic::Or,
                    negative: false,
                },
            ],
            matchers_condition: MatchLogic::And,
        },
        Template {
            id: "exposed-dotenv".into(),
            name: "Exposed .env file".into(),
            severity: "critical".into(),
            mitre: "T1552.001".into(),
            method: "GET".into(),
            path: "/.env".into(),
            headers: vec![],
            body: None,
            matchers: vec![
                Matcher {
                    matcher_type: "status".into(),
                    status: vec![200],
                    words: vec![],
                    part: Part::Body,
                    condition: MatchLogic::Or,
                    negative: false,
                },
                Matcher {
                    matcher_type: "word".into(),
                    status: vec![],
                    words: vec![
                        "DB_PASSWORD".into(),
                        "SECRET".into(),
                        "API_KEY".into(),
                        "AWS_".into(),
                    ],
                    part: Part::Body,
                    condition: MatchLogic::Or,
                    negative: false,
                },
            ],
            matchers_condition: MatchLogic::And,
        },
        Template {
            id: "spring-actuator-env".into(),
            name: "Spring Boot Actuator /env exposed".into(),
            severity: "high".into(),
            mitre: "T1592".into(),
            method: "GET".into(),
            path: "/actuator/env".into(),
            headers: vec![],
            body: None,
            matchers: vec![
                Matcher {
                    matcher_type: "status".into(),
                    status: vec![200],
                    words: vec![],
                    part: Part::Body,
                    condition: MatchLogic::Or,
                    negative: false,
                },
                Matcher {
                    matcher_type: "word".into(),
                    status: vec![],
                    words: vec!["propertySources".into()],
                    part: Part::Body,
                    condition: MatchLogic::And,
                    negative: false,
                },
            ],
            matchers_condition: MatchLogic::And,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &str, body: &str) -> HttpResponseView {
        HttpResponseView {
            status,
            headers: headers.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn status_matcher() {
        let m = Matcher {
            matcher_type: "status".into(),
            status: vec![200, 301],
            words: vec![],
            part: Part::Body,
            condition: MatchLogic::Or,
            negative: false,
        };
        assert!(m.matches(&resp(200, "", "")));
        assert!(!m.matches(&resp(404, "", "")));
    }

    #[test]
    fn word_and_or_logic() {
        let and = Matcher {
            matcher_type: "word".into(),
            status: vec![],
            words: vec!["foo".into(), "bar".into()],
            part: Part::Body,
            condition: MatchLogic::And,
            negative: false,
        };
        assert!(and.matches(&resp(200, "", "foo and bar")));
        assert!(!and.matches(&resp(200, "", "only foo")));

        let or = Matcher {
            condition: MatchLogic::Or,
            ..and.clone()
        };
        assert!(or.matches(&resp(200, "", "only foo")));
        assert!(!or.matches(&resp(200, "", "neither")));
    }

    #[test]
    fn negative_matcher_inverts() {
        let m = Matcher {
            matcher_type: "word".into(),
            status: vec![],
            words: vec!["blocked".into()],
            part: Part::Body,
            condition: MatchLogic::Or,
            negative: true,
        };
        assert!(m.matches(&resp(200, "", "all good")));
        assert!(!m.matches(&resp(200, "", "request blocked")));
    }

    #[test]
    fn part_selects_headers_vs_body() {
        let m = Matcher {
            matcher_type: "word".into(),
            status: vec![],
            words: vec!["x-powered-by".into()],
            part: Part::Headers,
            condition: MatchLogic::Or,
            negative: false,
        };
        assert!(m.matches(&resp(200, "x-powered-by: php\n", "body")));
        assert!(!m.matches(&resp(200, "server: nginx\n", "x-powered-by in body")));
    }

    #[test]
    fn template_combines_matchers_with_and() {
        let t = &builtin_templates()[0]; // exposed-git-config
        assert!(t.evaluate(&resp(200, "", "[core]\nrepositoryformatversion = 0")));
        assert!(!t.evaluate(&resp(404, "", "[core]")));
        assert!(!t.evaluate(&resp(200, "", "not a git config")));
    }

    #[test]
    fn templates_roundtrip_json() {
        let json = serde_json::to_string(&builtin_templates()).expect("ser");
        let parsed = parse_templates(&json).expect("parse");
        assert_eq!(parsed.len(), builtin_templates().len());
        assert_eq!(parsed[0].id, "exposed-git-config");
    }

    #[test]
    fn dotenv_template_requires_secret_word() {
        let t = builtin_templates()
            .into_iter()
            .find(|t| t.id == "exposed-dotenv")
            .unwrap();
        assert!(t.evaluate(&resp(200, "", "DB_PASSWORD=hunter2")));
        // 200 but no secret-looking content → no match (avoids flagging a benign /.env 200).
        assert!(!t.evaluate(&resp(200, "", "<html>not found</html>")));
    }
}
