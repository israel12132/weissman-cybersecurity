//! Password Spray & Credential-Stuffing Posture — world-class, evidence-first, agentless.
//!
//! Modelled on the identity-attack surface that defines modern breach response (Microsoft
//! Entra ID / Defender for Identity, CrowdStrike Falcon Identity, Okta ThreatInsight, Mandiant
//! password-spray playbooks). Unlike naive scanners that fire two guesses and call it a day,
//! this engine performs a **controlled, safety-bounded spray simulation** with full login-surface
//! cartography — every finding requires a real HTTP observation; nothing is simulated.
//!
//! What it measures:
//!   * **Login-surface discovery** — 40+ canonical paths (OWA, ADFS, OAuth/OIDC token, ASP.NET,
//!     Rails, WordPress, generic REST) with auth-type fingerprinting (form, JSON API, OAuth redirect,
//!     SAML/SPNEGO, Basic).
//!   * **Rate-limit & lockout policy** — burst of synthetic `weissman_probe_*` attempts; detects
//!     HTTP 429/423, `Retry-After`, lockout phrases, CAPTCHA challenges (reCAPTCHA/hCaptcha/Turnstile).
//!   * **User-enumeration oracle** — differential status/body-length/error-message between probe
//!     usernames (CWE-204, MITRE T1110.004).
//!   * **MFA / step-up surface** — detects MFA redirects and challenge pages on failed auth.
//!   * **Federated SSO exposure** — ADFS/OAuth authorize endpoints reachable without pre-auth hardening.
//!   * **M365 / Entra tenant intelligence** — live `GetUserRealm.srf` (Managed vs Federated, auth URL).
//!   * **OIDC ROPC grant detection** — parses `grant_types_supported` for resource-owner password credentials.
//!   * **Exchange Autodiscover** — SOAP autodiscover for OWA/EWS login URLs from the mail namespace.
//!   * **Lockout-curve fingerprint** — records the exact attempt number that triggers lockout/rate-limit.
//!   * **X-Forwarded-For evasion surface** — tests whether rate limits are IP-only (bypassable behind CDN).
//!   * **Wiz-style attack-path synthesis** + quantified 0–100 credential-hygiene posture score.
//!   * **Supreme synthesis** — toxic combinations, 8-domain category scores, remediation roadmap,
//!     security graph (`ok_with_graph`), HSTS/cookie/PKCE transport probes, honest agent guidance.
//!
//! Safety contract: only obviously synthetic credentials (`weissman_probe_*` users + curated probe
//! passwords) are used; `dry_run` skips spray attempts; attempt caps + inter-attempt delays are
//! GUI-enforced; no account destruction beyond what any security scanner performs.
//!
//! GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1110.003 (Password Spraying), T1110.004 (Credential Stuffing),
//! T1078 (Valid Accounts), T1556 (Modify Authentication Process).

#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::module_name_repetitions
)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, http_get, http_post_json_with_headers, join_url, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};

#[path = "password_spray_supreme.rs"]
mod supreme;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub(crate) const ENGINE_ID: &str = "password_spray";
pub(crate) const MITRE_SPRAY: &str = "T1110.003";
pub(crate) const MITRE_STUFF: &str = "T1110.004";
pub(crate) const MITRE_VALID: &str = "T1078";

const DEFAULT_PATHS: &[&str] = &[
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/api/v2/login",
    "/api/auth",
    "/api/session",
    "/session",
    "/account/login",
    "/user/login",
    "/users/sign_in",
    "/admin/login",
    "/wp-login.php",
    "/Account/Login",
    "/oauth/token",
    "/oauth2/token",
    "/oauth2/authorize",
    "/adfs/ls/",
    "/adfs/oauth2/authorize",
    "/owa/",
    "/ews/Exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/.well-known/openid-configuration",
    "/api/authenticate",
    "/api/signin",
    "/api/users/login",
    "/auth/realms/master/protocol/openid-connect/token",
    "/realms/master/protocol/openid-connect/token",
    "/login.aspx",
    "/cgi-bin/login",
    "/portal/login",
    "/my.policy",
    "/remote/login",
];

const SMALL_USERS: &[&str] = &[
    "weissman_probe_admin",
    "weissman_probe_user1",
    "weissman_probe_helpdesk",
    "weissman_probe_info",
    "weissman_probe_service",
];

const MEDIUM_USERS: &[&str] = &[
    "weissman_probe_admin",
    "weissman_probe_administrator",
    "weissman_probe_user1",
    "weissman_probe_user2",
    "weissman_probe_helpdesk",
    "weissman_probe_support",
    "weissman_probe_info",
    "weissman_probe_hr",
    "weissman_probe_finance",
    "weissman_probe_it",
    "weissman_probe_service",
    "weissman_probe_guest",
    "weissman_probe_test",
    "weissman_probe_dev",
    "weissman_probe_ops",
];

const LARGE_USERS: &[&str] = &[
    "weissman_probe_admin",
    "weissman_probe_administrator",
    "weissman_probe_root",
    "weissman_probe_user1",
    "weissman_probe_user2",
    "weissman_probe_user3",
    "weissman_probe_helpdesk",
    "weissman_probe_support",
    "weissman_probe_info",
    "weissman_probe_hr",
    "weissman_probe_finance",
    "weissman_probe_it",
    "weissman_probe_service",
    "weissman_probe_guest",
    "weissman_probe_test",
    "weissman_probe_dev",
    "weissman_probe_ops",
    "weissman_probe_sales",
    "weissman_probe_marketing",
    "weissman_probe_legal",
    "weissman_probe_contractor",
    "weissman_probe_vendor",
    "weissman_probe_backup",
    "weissman_probe_monitor",
    "weissman_probe_api",
    "weissman_probe_sync",
    "weissman_probe_report",
    "weissman_probe_billing",
    "weissman_probe_payroll",
    "weissman_probe_security",
];

const SMALL_PASSWORDS: &[&str] = &["WeissmanProbe!2024", "Changeme123!", "Password1!"];

const MEDIUM_PASSWORDS: &[&str] = &[
    "WeissmanProbe!2024",
    "Changeme123!",
    "Password1!",
    "Winter2024!",
    "Summer2024!",
    "Welcome1!",
    "P@ssw0rd!",
    "Qwerty123!",
];

const LARGE_PASSWORDS: &[&str] = &[
    "WeissmanProbe!2024",
    "Changeme123!",
    "Password1!",
    "Winter2024!",
    "Summer2024!",
    "Welcome1!",
    "P@ssw0rd!",
    "Qwerty123!",
    "Company123!",
    "Letmein1!",
    "Admin123!",
    "Passw0rd!",
    "Spring2025!",
    "Autumn2024!",
    "Hello123!",
];

const LOCKOUT_MARKERS: &[&str] = &[
    "too many",
    "rate limit",
    "rate-limit",
    "locked",
    "lockout",
    "try again later",
    "attempts exceeded",
    "temporarily blocked",
    "account disabled",
    "slow down",
    "throttl",
];

const CAPTCHA_MARKERS: &[&str] = &[
    "recaptcha",
    "g-recaptcha",
    "hcaptcha",
    "turnstile",
    "cf-turnstile",
    "captcha",
];

const MFA_MARKERS: &[&str] = &[
    "two-factor",
    "two factor",
    "2fa",
    "mfa",
    "multi-factor",
    "verification code",
    "authenticator",
    "one-time",
    "otp",
    "security code",
];

const ENUM_USER_MARKERS: &[&str] = &[
    "user not found",
    "unknown user",
    "invalid username",
    "no account",
    "does not exist",
    "not registered",
    "unknown email",
];

const ENUM_PASS_MARKERS: &[&str] = &[
    "invalid password",
    "wrong password",
    "incorrect password",
    "bad password",
    "password incorrect",
    "authentication failed",
];

const SUBDOMAIN_PREFIXES: &[&str] = &[
    "login", "signin", "sso", "idp", "auth", "accounts", "owa", "mail", "portal", "vpn", "remote",
    "identity", "my", "secure", "access",
];

const SAML_METADATA_PATHS: &[&str] = &[
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/saml/metadata",
    "/saml2/metadata",
    "/metadata/saml",
    "/metadata/saml2",
];

const POLICY_PROBE_PATHS: &[&str] = &[
    "/register",
    "/signup",
    "/sign-up",
    "/create-account",
    "/api/register",
    "/api/v1/register",
    "/api/users",
    "/api/auth/register",
];

/// Microsoft Entra error codes observable from live token/login responses (evidence-only).
const AADSTS_USER_EXISTS: &[&str] = &["AADSTS50126", "AADSTS50055", "AADSTS50076", "AADSTS50057"];
const AADSTS_USER_MISSING: &[&str] = &["AADSTS50034", "AADSTS51004"];
const AADSTS_LOCKOUT: &[&str] = &["AADSTS50053", "AADSTS50131"];

const BREACH_PROBE_PASSWORD: &str = "Password123!";
const RANDOM_PROBE_PASSWORD: &str = "xK9#mP2$vL7@nQ4!zR8wT";

// ── Configuration ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ScanConfig {
    timeout_ms: u64,
    concurrency: usize,
    intensity: Intensity,
    paths: Vec<String>,
    usernames: Vec<String>,
    passwords: Vec<String>,
    delay_ms: u64,
    max_attempts: usize,
    domain: String,
    dry_run: bool,
    check_rate_limit: bool,
    check_lockout: bool,
    check_user_enum: bool,
    check_mfa_surface: bool,
    check_oauth_federation: bool,
    check_captcha: bool,
    check_form_login: bool,
    check_json_api: bool,
    check_m365_realm: bool,
    check_oidc_ropc: bool,
    check_autodiscover: bool,
    check_xff_bypass: bool,
    check_lockout_curve: bool,
    check_subdomain_login: bool,
    check_saml_metadata: bool,
    check_password_policy: bool,
    check_device_code: bool,
    check_basic_ntlm: bool,
    check_browser_differential: bool,
    check_breach_differential: bool,
    check_timing_enum: bool,
    check_lockout_decay: bool,
    check_entra_errors: bool,
    check_cors_login: bool,
    check_remediation_playbook: bool,
    check_hsts_auth: bool,
    check_webauthn_surface: bool,
    check_oidc_pkce: bool,
    check_cookie_security: bool,
    emit_agent_guidance: bool,
    timing_samples: usize,
    lockout_decay_ms: u64,
    subdomain_prefixes: Vec<String>,
    include_info: bool,
    attack_paths: bool,
    posture_score: bool,
    auth_header: Option<String>,
    cookies: Option<String>,
}

impl ScanConfig {
    fn load(cfg: &ArsenalConfig, host: &str) -> Self {
        let intensity = cfg.intensity();
        let profile = cfg.string_or("scan_profile", "full").to_ascii_lowercase();
        let wordlist = cfg.string_or("wordlist", "medium").to_ascii_lowercase();
        let (default_users, default_passwords) = match wordlist.as_str() {
            "small" | "light" => (SMALL_USERS, SMALL_PASSWORDS),
            "large" | "aggressive" | "max" => (LARGE_USERS, LARGE_PASSWORDS),
            _ => (MEDIUM_USERS, MEDIUM_PASSWORDS),
        };
        let custom_users = cfg.string_list("usernames");
        let custom_passwords = cfg.string_list("passwords");
        let usernames = if custom_users.is_empty() {
            default_users.iter().map(|s| (*s).to_string()).collect()
        } else {
            custom_users
        };
        let passwords = if custom_passwords.is_empty() {
            default_passwords.iter().map(|s| (*s).to_string()).collect()
        } else {
            custom_passwords
        };
        let max_attempts = match intensity {
            Intensity::Light => cfg.usize_or("max_attempts", 6).clamp(2, 24),
            Intensity::Normal => cfg.usize_or("max_attempts", 18).clamp(4, 48),
            Intensity::Aggressive => cfg.usize_or("max_attempts", 36).clamp(8, 96),
        };
        let mut dry_run = cfg.bool_or("dry_run", false);
        let check_rate_limit = cfg.bool_or("check_rate_limit", true);
        let check_lockout = cfg.bool_or("check_lockout", true);
        let mut check_user_enum = cfg.bool_or("check_user_enum", true);
        let check_mfa_surface = cfg.bool_or("check_mfa_surface", true);
        let mut check_oauth_federation = cfg.bool_or("check_oauth_federation", true);
        let mut check_captcha = cfg.bool_or("check_captcha", true);
        let check_form_login = cfg.bool_or("check_form_login", true);
        let check_json_api = cfg.bool_or("check_json_api", true);
        let mut check_m365_realm = cfg.bool_or("check_m365_realm", true);
        let mut check_oidc_ropc = cfg.bool_or("check_oidc_ropc", true);
        let mut check_autodiscover = cfg.bool_or("check_autodiscover", true);
        let mut check_xff_bypass = cfg.bool_or("check_xff_bypass", true);
        let check_lockout_curve = cfg.bool_or("check_lockout_curve", true);
        let check_subdomain_login = cfg.bool_or("check_subdomain_login", true);
        let check_saml_metadata = cfg.bool_or("check_saml_metadata", true);
        let check_password_policy = cfg.bool_or("check_password_policy", true);
        let check_device_code = cfg.bool_or("check_device_code", true);
        let check_basic_ntlm = cfg.bool_or("check_basic_ntlm", true);
        let check_browser_differential = cfg.bool_or("check_browser_differential", true);
        let check_breach_differential = cfg.bool_or("check_breach_differential", true);
        let check_timing_enum = cfg.bool_or("check_timing_enum", intensity != Intensity::Light);
        let check_lockout_decay = cfg.bool_or("check_lockout_decay", false);
        let check_entra_errors = cfg.bool_or("check_entra_errors", true);
        let check_cors_login = cfg.bool_or("check_cors_login", true);
        let check_remediation_playbook = cfg.bool_or("check_remediation_playbook", true);
        let check_hsts_auth = cfg.bool_or("check_hsts_auth", true);
        let check_webauthn_surface = cfg.bool_or("check_webauthn_surface", true);
        let check_oidc_pkce = cfg.bool_or("check_oidc_pkce", true);
        let check_cookie_security = cfg.bool_or("check_cookie_security", true);
        let emit_agent_guidance = cfg.bool_or("emit_agent_guidance", true);
        let timing_samples = cfg.usize_or("timing_samples", 8).clamp(4, 24);
        let lockout_decay_ms = cfg.u64_or("lockout_decay_ms", 30_000).clamp(5_000, 120_000);
        let subdomain_prefixes = if cfg.string_list("subdomain_prefixes").is_empty() {
            SUBDOMAIN_PREFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            cfg.string_list("subdomain_prefixes")
        };
        let mut paths = cfg.string_list_or("paths", DEFAULT_PATHS);
        match profile.as_str() {
            "discovery_only" | "discovery" => {
                dry_run = true;
                check_user_enum = false;
                check_xff_bypass = false;
            }
            "spray_test" | "spray" => {
                check_oauth_federation = false;
                check_m365_realm = false;
                check_autodiscover = false;
            }
            "federation" | "federated" => {
                paths = paths
                    .into_iter()
                    .filter(|p| {
                        let pl = p.to_ascii_lowercase();
                        pl.contains("adfs")
                            || pl.contains("oauth")
                            || pl.contains("openid")
                            || pl.contains("saml")
                            || pl.contains("owa")
                    })
                    .collect();
                if paths.is_empty() {
                    paths = vec![
                        "/adfs/ls/".into(),
                        "/adfs/oauth2/authorize".into(),
                        "/oauth2/authorize".into(),
                        "/owa/".into(),
                        "/.well-known/openid-configuration".into(),
                    ];
                }
                check_user_enum = false;
                check_captcha = false;
                check_m365_realm = true;
                check_oidc_ropc = true;
            }
            _ => {}
        }
        Self {
            timeout_ms: cfg.timeout_ms(10_000),
            concurrency: cfg.concurrency().clamp(1, 24),
            intensity,
            paths,
            usernames,
            passwords,
            delay_ms: cfg.u64_or("delay_ms", 1500).clamp(200, 30_000),
            max_attempts,
            domain: cfg.string_or("domain", host),
            dry_run,
            check_rate_limit,
            check_lockout,
            check_user_enum,
            check_mfa_surface,
            check_oauth_federation,
            check_captcha,
            check_form_login,
            check_json_api,
            check_m365_realm,
            check_oidc_ropc,
            check_autodiscover,
            check_xff_bypass,
            check_lockout_curve,
            check_subdomain_login,
            check_saml_metadata,
            check_password_policy,
            check_device_code,
            check_basic_ntlm,
            check_browser_differential,
            check_breach_differential,
            check_timing_enum,
            check_lockout_decay,
            check_entra_errors,
            check_cors_login,
            check_remediation_playbook,
            check_hsts_auth,
            check_webauthn_surface,
            check_oidc_pkce,
            check_cookie_security,
            emit_agent_guidance,
            timing_samples,
            lockout_decay_ms,
            subdomain_prefixes,
            include_info: cfg.bool_or("include_info_findings", true),
            attack_paths: cfg.bool_or("attack_path_synthesis", true),
            posture_score: cfg.bool_or("posture_scoring", true),
            auth_header: cfg.string("auth_header"),
            cookies: cfg.string("cookies"),
        }
    }
}

fn build_client(timeout_ms: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-PasswordSpray/1.0")
        .redirect(reqwest::redirect::Policy::limited(4))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn parse_auth_header(h: &str) -> Vec<(&str, &str)> {
    if let Some((k, v)) = h.split_once(':') {
        vec![(k.trim(), v.trim())]
    } else {
        vec![]
    }
}

pub(crate) fn with_fields(mut f: Value, extra: &[(&str, Value)]) -> Value {
    if let Some(obj) = f.as_object_mut() {
        for (k, v) in extra {
            obj.insert(k.to_string(), v.clone());
        }
    }
    f
}

fn body_lower(body: &str) -> String {
    body.to_ascii_lowercase()
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

// ── Login surface model ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub(crate) struct LoginSurface {
    url: String,
    auth_type: String,
    status: u16,
    federated: bool,
    mfa_hint: bool,
    #[allow(dead_code)] // detected on login surface; not read after refactor
    captcha_hint: bool,
}

#[derive(Clone, Debug, Default)]
struct SprayOutcome {
    attempts: u32,
    rate_limited: bool,
    locked: bool,
    captcha_triggered: bool,
    mfa_step_up: bool,
    first_429_at: Option<u32>,
    lockout_at: Option<u32>,
    lockout_phrase: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SprayPosture {
    pub(crate) login_surfaces: Vec<LoginSurface>,
    no_rate_limit: Vec<String>,
    no_lockout: Vec<String>,
    user_enum: Vec<String>,
    captcha_absent: Vec<String>,
    mfa_absent: Vec<String>,
    federated_exposed: Vec<String>,
    verbose_errors: Vec<String>,
    ropc_enabled: Vec<String>,
    xff_bypassable: Vec<String>,
    m365_federated: bool,
    lockout_curves: Vec<(String, u32)>,
    saml_exposed: Vec<String>,
    device_code_enabled: Vec<String>,
    subdomain_logins: Vec<String>,
    basic_auth_surfaces: Vec<String>,
    browser_waf_gaps: Vec<String>,
    timing_enum_surfaces: Vec<String>,
    breach_oracles: Vec<String>,
    entra_signals: Vec<String>,
    cors_permissive: Vec<String>,
    short_lockout_decay: Vec<String>,
    transport_gaps: Vec<String>,
    cookie_gaps: Vec<String>,
    webauthn_surfaces: Vec<String>,
}

impl SprayPosture {
    pub(crate) fn score(&self) -> u32 {
        let mut s: i32 = 100;
        s -= (self.no_rate_limit.len() as i32).min(2) * 22;
        s -= (self.no_lockout.len() as i32).min(2) * 18;
        s -= (self.user_enum.len() as i32).min(3) * 12;
        s -= (self.captcha_absent.len() as i32).min(2) * 8;
        s -= (self.mfa_absent.len() as i32).min(2) * 10;
        s -= (self.federated_exposed.len() as i32).min(2) * 8;
        s -= (self.verbose_errors.len() as i32).min(2) * 6;
        s -= (self.ropc_enabled.len() as i32).min(2) * 15;
        s -= (self.xff_bypassable.len() as i32).min(2) * 12;
        if self.m365_federated {
            s -= 5;
        }
        s -= (self.saml_exposed.len() as i32).min(2) * 8;
        s -= (self.device_code_enabled.len() as i32).min(1) * 10;
        s -= (self.browser_waf_gaps.len() as i32).min(2) * 9;
        s -= (self.timing_enum_surfaces.len() as i32).min(2) * 11;
        s -= (self.breach_oracles.len() as i32).min(2) * 7;
        s -= (self.cors_permissive.len() as i32).min(1) * 8;
        s -= (self.short_lockout_decay.len() as i32).min(1) * 12;
        s -= (self.login_surfaces.len().saturating_sub(1) as i32).min(4) * 3;
        s.clamp(0, 100) as u32
    }

    fn grade(score: u32) -> &'static str {
        match score {
            95..=100 => "A+",
            90..=94 => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        }
    }

    fn has_any(&self) -> bool {
        !self.no_rate_limit.is_empty()
            || !self.no_lockout.is_empty()
            || !self.user_enum.is_empty()
            || !self.federated_exposed.is_empty()
            || !self.ropc_enabled.is_empty()
            || !self.xff_bypassable.is_empty()
            || self.m365_federated
            || !self.saml_exposed.is_empty()
            || !self.browser_waf_gaps.is_empty()
    }

    /// Six-axis posture radar (each 0–100, higher = better control).
    fn radar(&self) -> Value {
        let axis = |gap_count: usize, weight: i32| -> u32 {
            (100 - (gap_count as i32).min(3) * weight).clamp(0, 100) as u32
        };
        json!({
            "rate_limit": axis(self.no_rate_limit.len(), 25),
            "lockout": axis(self.no_lockout.len(), 30),
            "mfa": axis(self.mfa_absent.len(), 20),
            "enumeration": axis(self.user_enum.len() + self.timing_enum_surfaces.len(), 18),
            "federation_hygiene": axis(self.federated_exposed.len() + self.saml_exposed.len() + if self.m365_federated { 1 } else { 0 }, 15),
            "automation_resistance": axis(self.browser_waf_gaps.len() + self.cors_permissive.len() + self.xff_bypassable.len(), 20),
        })
    }

    /// Composite 0–1 friction index — how hard credential stuffing is for an attacker.
    pub(crate) fn stuffing_friction(&self) -> f64 {
        let mut risk = 0.12f64;
        if !self.no_rate_limit.is_empty() {
            risk += 0.28;
        }
        if !self.no_lockout.is_empty() {
            risk += 0.22;
        }
        if !self.captcha_absent.is_empty() {
            risk += 0.14;
        }
        if !self.mfa_absent.is_empty() {
            risk += 0.18;
        }
        if !self.user_enum.is_empty() {
            risk += 0.08;
        }
        if !self.ropc_enabled.is_empty() {
            risk += 0.08;
        }
        risk.clamp(0.0, 1.0)
    }
}

fn fingerprint_auth_type(
    path: &str,
    status: u16,
    body: &str,
    headers: &[(String, String)],
) -> (String, bool) {
    let bl = body_lower(body);
    let pl = path.to_ascii_lowercase();
    let loc = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    if pl.contains("adfs") || pl.contains("oauth") || pl.contains("openid") || pl.contains("saml") {
        return ("oauth_federation".into(), true);
    }
    if loc.contains("login.microsoftonline.com")
        || loc.contains("adfs")
        || loc.contains("okta")
        || bl.contains("saml")
        || bl.contains("ws-federation")
    {
        return ("oauth_federation".into(), true);
    }
    if bl.contains("<form") && (bl.contains("password") || bl.contains("passwd")) {
        return ("html_form".into(), false);
    }
    if bl.contains("application/json") || pl.contains("/api/") || pl.contains("/oauth") {
        return ("json_api".into(), false);
    }
    if status == 401 {
        let www = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        if www.contains("basic") || www.contains("negotiate") || www.contains("ntlm") {
            return ("http_auth".into(), www.contains("negotiate"));
        }
    }
    if status == 200 || status == 401 || status == 403 {
        return ("login_surface".into(), false);
    }
    ("unknown".into(), false)
}

async fn discover_surface(
    client: &Client,
    base: &str,
    path: &str,
    _cfg: &ScanConfig,
    extra: &[(&str, &str)],
) -> Option<LoginSurface> {
    let url = join_url(base, path);
    let probe = http_get_with_extra(client, &url, extra).await?;
    if !matches!(probe.status, 200 | 302 | 307 | 401 | 403 | 405) {
        return None;
    }
    let bl = body_lower(&probe.body);
    let (auth_type, federated) =
        fingerprint_auth_type(path, probe.status, &probe.body, &probe.headers);
    let login_hint = bl.contains("password")
        || bl.contains("sign in")
        || bl.contains("log in")
        || bl.contains("username")
        || federated
        || path.contains("login")
        || path.contains("signin")
        || path.contains("adfs")
        || path.contains("oauth");
    if !login_hint && probe.status != 401 {
        return None;
    }
    Some(LoginSurface {
        url: url.clone(),
        auth_type,
        status: probe.status,
        federated,
        mfa_hint: contains_any(&bl, MFA_MARKERS),
        captcha_hint: contains_any(&bl, CAPTCHA_MARKERS),
    })
}

struct HttpResp {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

async fn http_get_with_extra(
    client: &Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Option<HttpResp> {
    let mut req = client.get(url);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 32_768 {
        body[..32_768].to_string()
    } else {
        body
    };
    Some(HttpResp {
        status,
        body,
        headers,
    })
}

async fn attempt_json_login(
    client: &Client,
    url: &str,
    username: &str,
    password: &str,
    extra: &[(&str, &str)],
) -> Option<HttpResp> {
    for payload in [
        json!({"username": username, "password": password}),
        json!({"user": username, "password": password}),
        json!({"email": username, "password": password}),
        json!({"login": username, "password": password}),
    ] {
        if let Some(p) = http_post_json_with_headers(client, url, &payload, extra).await {
            return Some(HttpResp {
                status: p.status,
                body: p.body,
                headers: p.headers,
            });
        }
    }
    None
}

async fn attempt_form_login(
    client: &Client,
    url: &str,
    username: &str,
    password: &str,
    extra: &[(&str, &str)],
) -> Option<HttpResp> {
    let mut req = client.post(url).form(&[
        ("username", username),
        ("password", password),
        ("user", username),
        ("pass", password),
        ("email", username),
    ]);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 32_768 {
        body[..32_768].to_string()
    } else {
        body
    };
    Some(HttpResp {
        status,
        body,
        headers,
    })
}

fn analyze_attempt(resp: &HttpResp, attempt_no: u32) -> SprayOutcome {
    let bl = body_lower(&resp.body);
    let rate_limited = resp.status == 429
        || resp.status == 503
        || resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("retry-after") && !v.trim().is_empty());
    let locked = resp.status == 423 || contains_any(&bl, LOCKOUT_MARKERS);
    let captcha = contains_any(&bl, CAPTCHA_MARKERS);
    let mfa = contains_any(&bl, MFA_MARKERS)
        || resp.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("location") && contains_any(&v.to_ascii_lowercase(), MFA_MARKERS)
        });
    SprayOutcome {
        attempts: attempt_no,
        rate_limited,
        locked,
        captcha_triggered: captcha,
        mfa_step_up: mfa,
        first_429_at: if rate_limited { Some(attempt_no) } else { None },
        lockout_at: if locked { Some(attempt_no) } else { None },
        lockout_phrase: LOCKOUT_MARKERS
            .iter()
            .find(|m| bl.contains(*m))
            .map(|s| (*s).to_string()),
    }
}

async fn run_spray_simulation(
    client: &Client,
    surface: &LoginSurface,
    cfg: &ScanConfig,
    extra: &[(&str, &str)],
) -> SprayOutcome {
    let mut outcome = SprayOutcome::default();
    let mut attempt_no = 0u32;
    let mut combos: Vec<(&str, &str)> = Vec::new();
    for u in cfg.usernames.iter().take(cfg.max_attempts) {
        for p in &cfg.passwords {
            if combos.len() >= cfg.max_attempts {
                break;
            }
            combos.push((u.as_str(), p.as_str()));
        }
        if combos.len() >= cfg.max_attempts {
            break;
        }
    }

    for (user, pass) in combos {
        attempt_no += 1;
        let resp = if surface.auth_type == "html_form" && cfg.check_form_login {
            attempt_form_login(client, &surface.url, user, pass, extra).await
        } else if cfg.check_json_api {
            attempt_json_login(client, &surface.url, user, pass, extra).await
        } else {
            None
        };
        let Some(r) = resp else {
            continue;
        };
        let snap = analyze_attempt(&r, attempt_no);
        if snap.rate_limited {
            outcome.rate_limited = true;
            outcome.first_429_at = snap.first_429_at.or(Some(attempt_no));
            break;
        }
        if snap.locked {
            outcome.locked = true;
            outcome.lockout_at = Some(attempt_no);
            outcome.lockout_phrase = snap.lockout_phrase;
            break;
        }
        if snap.captcha_triggered {
            outcome.captcha_triggered = true;
        }
        if snap.mfa_step_up {
            outcome.mfa_step_up = true;
        }
        outcome.attempts = attempt_no;
        if attempt_no < cfg.max_attempts as u32 {
            sleep(Duration::from_millis(cfg.delay_ms)).await;
        }
    }
    outcome
}

async fn probe_user_enumeration(
    client: &Client,
    url: &str,
    cfg: &ScanConfig,
    extra: &[(&str, &str)],
) -> Option<(String, Evidence)> {
    let user_a = format!("weissman_probe_enum_known@{}", cfg.domain);
    let user_b = "weissman_probe_enum_xyz_nonexistent_9f3a";
    let pass = "WeissmanProbe!Invalid";
    let ra = attempt_json_login(client, url, &user_a, pass, extra).await?;
    let rb = attempt_json_login(client, url, user_b, pass, extra).await?;
    let bl_a = body_lower(&ra.body);
    let bl_b = body_lower(&rb.body);
    let status_diff = ra.status != rb.status;
    let len_a = ra.body.len();
    let len_b = rb.body.len();
    let len_diff = len_a.abs_diff(len_b) > (len_a.max(len_b) / 10).max(24);
    let enum_a = contains_any(&bl_a, ENUM_USER_MARKERS);
    let enum_b = contains_any(&bl_b, ENUM_PASS_MARKERS);
    let msg_diff = enum_a || (enum_a != enum_b && contains_any(&bl_b, ENUM_USER_MARKERS));
    if status_diff || len_diff || msg_diff {
        let ev = Evidence::new()
            .with("url", url)
            .with("status_a", ra.status)
            .with("status_b", rb.status)
            .with("body_len_a", len_a)
            .with("body_len_b", len_b)
            .check(
                "status_differential",
                status_diff,
                format!("{} vs {}", ra.status, rb.status),
            )
            .check(
                "body_length_differential",
                len_diff,
                format!("{len_a} vs {len_b}"),
            )
            .check(
                "error_message_differential",
                msg_diff,
                "distinct user-existence signals",
            );
        return Some(("user_enumeration".into(), ev));
    }
    None
}

fn surface_findings(
    target: &str,
    surface: &LoginSurface,
    spray: &SprayOutcome,
    cfg: &ScanConfig,
    posture: &mut SprayPosture,
) -> Vec<Value> {
    let mut out = Vec::new();
    posture.login_surfaces.push(surface.clone());

    let ev_base = Evidence::new()
        .with("url", surface.url.clone())
        .with("auth_type", surface.auth_type.clone())
        .with("http_status", surface.status)
        .with("federated", surface.federated);

    out.push(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Login surface: {} ({})", surface.url, surface.auth_type),
            if surface.federated { "medium" } else { "low" },
            MITRE_VALID,
            &format!(
                "Discovered an authentication entry point at {} — type `{}`{}.",
                surface.url,
                surface.auth_type,
                if surface.federated {
                    " (federated SSO)"
                } else {
                    ""
                }
            ),
            target,
            0.95,
            ev_base.clone(),
        ),
        &[("category", json!("login_surface"))],
    ));

    if surface.federated && cfg.check_oauth_federation {
        posture.federated_exposed.push(surface.url.clone());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Federated SSO endpoint exposed: {}", surface.url),
                "medium",
                MITRE_VALID,
                "An OAuth/ADFS/SAML federation endpoint is reachable. Ensure lockout, MFA, and conditional access policies apply before password spray reaches the IdP.",
                target,
                0.9,
                ev_base.clone().check("federated", true, "SSO redirect or federation surface"),
            ),
            &[("category", json!("federation_exposure"))],
        ));
    }

    if cfg.dry_run {
        return out;
    }

    if cfg.check_rate_limit && spray.attempts > 0 && !spray.rate_limited {
        posture.no_rate_limit.push(surface.url.clone());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("No HTTP rate-limiting after {} spray attempts: {}", spray.attempts, surface.url),
                "high",
                MITRE_SPRAY,
                &format!(
                    "{} synthetic spray attempts against {} did not trigger HTTP 429/503 or Retry-After. \
                     Credential spraying and stuffing attacks may proceed at scale.",
                    spray.attempts, surface.url
                ),
                target,
                0.88,
                ev_base
                    .clone()
                    .with("attempts", spray.attempts)
                    .check("rate_limit", false, "no 429/Retry-After observed"),
            ),
            &[("category", json!("rate_limit_gap"))],
        ));
    }

    if cfg.check_lockout && spray.attempts > 1 && !spray.locked && !spray.rate_limited {
        posture.no_lockout.push(surface.url.clone());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("No account lockout detected: {}", surface.url),
                "high",
                MITRE_SPRAY,
                &format!(
                    "Multiple failed authentications at {} did not produce HTTP 423 or lockout messaging. \
                     Per-user lockout policy may be absent.",
                    surface.url
                ),
                target,
                0.82,
                ev_base
                    .clone()
                    .with("attempts", spray.attempts)
                    .check("lockout", false, "no 423/lockout phrase"),
            ),
            &[("category", json!("lockout_gap"))],
        ));
    }

    if cfg.check_captcha && spray.attempts > 2 && !spray.captcha_triggered && !spray.rate_limited {
        posture.captcha_absent.push(surface.url.clone());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("No CAPTCHA challenge after failed logins: {}", surface.url),
                "medium",
                MITRE_STUFF,
                "Failed login attempts did not surface a CAPTCHA/Turnstile challenge — automated stuffing tooling faces less friction.",
                target,
                0.75,
                ev_base.clone().check("captcha", false, "no challenge observed"),
            ),
            &[("category", json!("captcha_gap"))],
        ));
    }

    if cfg.check_mfa_surface && spray.attempts > 0 && !spray.mfa_step_up && !surface.mfa_hint {
        posture.mfa_absent.push(surface.url.clone());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("No MFA step-up on failed authentication: {}", surface.url),
                "medium",
                MITRE_VALID,
                "Failed logins did not redirect to MFA/2FA verification — password-only compromise may suffice.",
                target,
                0.7,
                ev_base.clone().check("mfa_step_up", false, "no MFA challenge"),
            ),
            &[("category", json!("mfa_gap"))],
        ));
    }

    if spray.rate_limited {
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Rate-limiting enforced at attempt #{}: {}", spray.first_429_at.unwrap_or(spray.attempts), surface.url),
                "info",
                MITRE_SPRAY,
                "The endpoint returned rate-limit signals during the controlled spray — credential stuffing blast radius is constrained.",
                target,
                1.0,
                ev_base
                    .with("attempts", spray.attempts)
                    .check("rate_limit", true, "429/Retry-After observed"),
            ),
            &[("category", json!("control_effective"))],
        ));
    }

    out
}

fn synthesize_attack_paths(target: &str, posture: &SprayPosture, host: &str) -> Vec<Value> {
    if !posture.has_any() {
        return vec![];
    }
    let mut paths = Vec::new();
    if !posture.no_rate_limit.is_empty() && !posture.user_enum.is_empty() {
        paths.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: enumerate → spray → valid account",
                "critical",
                MITRE_STUFF,
                &format!(
                    "Combine user-enumeration oracles on {host} with absent rate-limiting on {:?} to run a targeted password spray, then pivot with valid credentials (T1078).",
                    posture.no_rate_limit.first()
                ),
                target,
                0.92,
                Evidence::new()
                    .with("stage_1", "user_enumeration")
                    .with("stage_2", "password_spray")
                    .with("stage_3", "valid_account_pivot"),
            ),
            &[("category", json!("attack_path"))],
        ));
    } else if !posture.no_rate_limit.is_empty() {
        paths.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: distributed password spray",
                "high",
                MITRE_SPRAY,
                &format!(
                    "Absent rate-limiting on {:?} enables low-and-slow distributed spraying across {} discovered surface(s).",
                    posture.no_rate_limit.first(),
                    posture.login_surfaces.len()
                ),
                target,
                0.85,
                Evidence::new()
                    .with("stage_1", "password_spray")
                    .with("surfaces", posture.login_surfaces.len()),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.federated_exposed.is_empty() && !posture.mfa_absent.is_empty() {
        paths.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: federated spray → IdP session",
                "high",
                MITRE_VALID,
                &format!(
                    "Federated endpoint {:?} may accept sprayed credentials against the upstream IdP without per-attempt MFA — breach of SSO trust.",
                    posture.federated_exposed.first()
                ),
                target,
                0.8,
                Evidence::new()
                    .with("stage_1", "federated_login_spray")
                    .with("stage_2", "sso_token_acquisition"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    if !posture.ropc_enabled.is_empty() {
        paths.push(with_fields(
            finding_rich(
                ENGINE_ID,
                "Attack path: ROPC token-endpoint spray → API access",
                "critical",
                MITRE_STUFF,
                &format!(
                    "OIDC password grant on {:?} allows direct token acquisition from spray — bypasses browser MFA and enables API-level pivot.",
                    posture.ropc_enabled.first()
                ),
                target,
                0.95,
                Evidence::new()
                    .with("stage_1", "ropc_password_spray")
                    .with("stage_2", "bearer_token_pivot"),
            ),
            &[("category", json!("attack_path"))],
        ));
    }
    paths
}

// ── Tenant intelligence (real external probes — nothing simulated) ────────────

async fn probe_m365_user_realm(client: &Client, domain: &str, target: &str) -> Option<Value> {
    let login = format!("weissman_probe@{domain}");
    let url = format!(
        "https://login.microsoftonline.com/getuserrealm.srf?login={}&json=1",
        urlencoding::encode(&login)
    );
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status != 200 || body.trim().is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(&body).ok()?;
    let ns = parsed
        .get("NameSpaceType")
        .and_then(Value::as_str)
        .unwrap_or("Unknown");
    let federated = ns.eq_ignore_ascii_case("Federated");
    let auth_url = parsed
        .get("AuthURL")
        .or_else(|| parsed.get("federation_global_url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let cloud_instance = parsed
        .get("cloud_instance_name")
        .and_then(Value::as_str)
        .unwrap_or("microsoftonline.com");
    let severity = if federated { "medium" } else { "info" };
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Microsoft Entra tenant: {ns} ({domain})"),
            severity,
            MITRE_VALID,
            if federated {
                "GetUserRealm.srf confirms a **Federated** Entra ID tenant — password spray typically targets the on-prem ADFS/IdP endpoint, not Azure AD directly. Map federation AuthURL and enforce IdP lockout policies."
            } else if ns.eq_ignore_ascii_case("Managed") {
                "GetUserRealm.srf confirms a **Managed** Entra ID (cloud-only) tenant — spray targets login.microsoftonline.com with smart lockout and Conditional Access as primary controls."
            } else {
                "GetUserRealm.srf returned a live tenant signal for this domain namespace."
            },
            target,
            0.95,
            Evidence::new()
                .with("domain", domain)
                .with("namespace_type", ns)
                .with("auth_url", auth_url)
                .with("cloud_instance", cloud_instance)
                .with("probe_url", url)
                .check("getuserrealm", true, status),
        ),
        &[("category", json!("m365_realm"))],
    ))
}

async fn probe_oidc_ropc(client: &Client, base: &str, target: &str) -> Option<Value> {
    const DISCOVERY: &[&str] = &[
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth2/.well-known/openid-configuration",
    ];
    for path in DISCOVERY {
        let url = join_url(base, path);
        let Some(p) = http_get(client, &url).await else {
            continue;
        };
        if p.status != 200 {
            continue;
        }
        let doc: Value = serde_json::from_str(&p.body).ok()?;
        let grants = doc
            .get("grant_types_supported")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !grants.iter().any(|g| g == "password") {
            continue;
        }
        let token_ep = doc
            .get("token_endpoint")
            .and_then(Value::as_str)
            .unwrap_or("");
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                "OIDC Resource Owner Password Credentials (ROPC) enabled",
                "critical",
                MITRE_SPRAY,
                &format!(
                    "OIDC discovery at {url} advertises `password` in grant_types_supported{} — \
                     attackers can spray credentials directly against the token endpoint without a browser. \
                     Disable ROPC per RFC 9700 / Entra security guidance.",
                    if token_ep.is_empty() {
                        String::new()
                    } else {
                        format!(" (token_endpoint: {token_ep})")
                    }
                ),
                target,
                0.98,
                Evidence::new()
                    .with("discovery_url", url)
                    .with("grant_types_supported", json!(grants))
                    .with("token_endpoint", token_ep)
                    .check("ropc_grant", true, "password grant advertised"),
            ),
            &[("category", json!("oidc_ropc"))],
        ));
    }
    None
}

async fn probe_exchange_autodiscover(client: &Client, domain: &str, target: &str) -> Option<Value> {
    let url = format!("https://autodiscover.{domain}/autodiscover/autodiscover.svc");
    let soap = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover"
 xmlns:wsa="http://www.w3.org/2005/08/addressing"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header><a:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetUserSettings</a:Action>
  <a:To>https://autodiscover.{domain}/autodiscover/autodiscover.svc</a:To></soap:Header>
  <soap:Body><a:GetUserSettings><a:Request><a:Users><a:User><a:Mailbox>weissman_probe@{domain}</a:Mailbox></a:User></a:Users>
  <a:RequestedSettings><a:Setting>ExternalUrl</a:Setting><a:Setting>InternalUrl</a:Setting></a:RequestedSettings>
  </a:Request></a:GetUserSettings></soap:Body></soap:Envelope>"#
    );
    let resp = client
        .post(&url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(soap)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status != 200 || body.is_empty() {
        return None;
    }
    let bl = body.to_ascii_lowercase();
    let owa = bl.contains("owa") || bl.contains("outlook");
    let ews = bl.contains("ews") || bl.contains("exchange.asmx");
    if !owa && !ews {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Exchange Autodiscover resolved mail auth URLs ({domain})"),
            "medium",
            MITRE_SPRAY,
            "Live SOAP Autodiscover returned OWA/EWS endpoints — additional password-spray surfaces beyond generic /login paths. Harden with modern auth, lockout, and disable basic auth.",
            target,
            0.9,
            Evidence::new()
                .with("autodiscover_url", url)
                .with("http_status", status)
                .check("owa_surface", owa, "OWA URL in response")
                .check("ews_surface", ews, "EWS URL in response")
                .raw_excerpt(body.as_bytes()),
        ),
        &[("category", json!("autodiscover"))],
    ))
}

async fn probe_xff_rate_limit_surface(
    client: &Client,
    surface: &LoginSurface,
    cfg: &ScanConfig,
    extra: &[(&str, &str)],
    target: &str,
) -> Option<Value> {
    if surface.auth_type == "oauth_federation" {
        return None;
    }
    let user = "weissman_probe_xff_a";
    let pass = "WeissmanProbe!XFF";
    let mut baseline_blocked = false;
    for i in 0..3u32 {
        let Some(r) = attempt_json_login(client, &surface.url, user, pass, extra).await else {
            return None;
        };
        if r.status == 429 || r.status == 423 {
            baseline_blocked = true;
            break;
        }
        if i < 2 {
            sleep(Duration::from_millis(cfg.delay_ms / 2)).await;
        }
    }
    if baseline_blocked {
        return None;
    }
    let mut xff_extra: Vec<(&str, &str)> = extra.to_vec();
    for (i, ip) in ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
        .iter()
        .enumerate()
    {
        xff_extra.retain(|(k, _)| *k != "X-Forwarded-For");
        xff_extra.push(("X-Forwarded-For", ip));
        let Some(r) = attempt_json_login(client, &surface.url, user, pass, &xff_extra).await else {
            continue;
        };
        if r.status == 429 || r.status == 423 {
            return None;
        }
        if i < 2 {
            sleep(Duration::from_millis(cfg.delay_ms / 2)).await;
        }
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("IP-only rate limiting (X-Forwarded-For bypass surface): {}", surface.url),
            "high",
            MITRE_SPRAY,
            "Rotating X-Forwarded-For across failed login attempts did not trigger rate-limit/lockout while baseline attempts also passed — controls may key only on client IP, bypassable via CDN header injection or distributed egress.",
            target,
            0.84,
            Evidence::new()
                .with("url", surface.url.clone())
                .check("xff_rotation", true, "3 distinct X-Forwarded-For values, no 429")
                .check("baseline_unblocked", true, "baseline attempts also unblocked"),
        ),
        &[("category", json!("xff_bypass"))],
    ))
}

fn lockout_curve_finding(
    target: &str,
    surface: &LoginSurface,
    spray: &SprayOutcome,
) -> Option<Value> {
    let at = spray.lockout_at.or(spray.first_429_at)?;
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Lockout curve: threshold at attempt #{at} — {}", surface.url),
            if at <= 3 { "high" } else { "medium" },
            MITRE_SPRAY,
            &format!(
                "Controlled spray simulation triggered defensive response at attempt #{at}{}. \
                 Low thresholds increase credential-stuffing cost; high thresholds widen spray windows.",
                spray
                    .lockout_phrase
                    .as_ref()
                    .map(|p| format!(" (signal: `{p}`)"))
                    .unwrap_or_default()
            ),
            target,
            0.92,
            Evidence::new()
                .with("url", surface.url.clone())
                .with("lockout_attempt", at)
                .with("total_attempts", spray.attempts)
                .check("lockout_curve", true, at),
        ),
        &[("category", json!("lockout_curve"))],
    ))
}

async fn hunt_subdomain_logins(
    client: &Client,
    domain: &str,
    prefixes: &[String],
    target: &str,
    concurrency: usize,
) -> Vec<Value> {
    let cap = prefixes.len().min(14);
    let urls: Vec<String> = prefixes
        .iter()
        .take(cap)
        .flat_map(|p| {
            [
                format!("https://{p}.{domain}/login"),
                format!("https://{p}.{domain}/signin"),
                format!("https://{p}.{domain}/"),
            ]
        })
        .collect();
    stream::iter(urls)
        .map(|url| {
            let client = client.clone();
            let target = target.to_string();
            async move {
                let p = http_get(&client, &url).await?;
                if !matches!(p.status, 200 | 302 | 401 | 403) {
                    return None;
                }
                let bl = body_lower(&p.body);
                if !(bl.contains("password") || bl.contains("sign in") || bl.contains("login") || p.status == 401)
                {
                    return None;
                }
                Some(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Subdomain login surface: {url}"),
                        "medium",
                        MITRE_VALID,
                        "Discovered an additional authentication host outside the primary target URL — expands spray blast radius for red-team / assesses shadow SSO entry points.",
                        &target,
                        0.9,
                        Evidence::new()
                            .with("url", url.clone())
                            .with("http_status", p.status)
                            .check("subdomain_login", true, "login UI or 401 on subdomain"),
                    ),
                    &[("category", json!("subdomain_login"))],
                ))
            }
        })
        .buffer_unordered(concurrency.clamp(1, 16))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

async fn probe_saml_metadata(client: &Client, base: &str, target: &str) -> Option<Value> {
    for path in SAML_METADATA_PATHS {
        let url = join_url(base, path);
        let Some(p) = http_get(client, &url).await else {
            continue;
        };
        if p.status != 200 {
            continue;
        }
        let bl = body_lower(&p.body);
        if !(bl.contains("entitydescriptor")
            || bl.contains("idpssodescriptor")
            || bl.contains("saml"))
        {
            continue;
        }
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("SAML federation metadata exposed: {url}"),
                "high",
                MITRE_VALID,
                "Live SAML metadata is reachable without authentication — reveals IdP endpoints, certificates, and binding URLs useful for credential spray and SAML attack planning.",
                target,
                0.93,
                Evidence::new()
                    .with("url", url)
                    .check("saml_metadata", true, "EntityDescriptor/IDPSSODescriptor observed"),
            ),
            &[("category", json!("saml_metadata"))],
        ));
    }
    None
}

async fn probe_password_policy_oracle(client: &Client, base: &str, target: &str) -> Option<Value> {
    for path in POLICY_PROBE_PATHS {
        let url = join_url(base, path);
        let payload = json!({
            "username": "weissman_probe_policy",
            "email": "weissman_probe_policy@example.com",
            "password": "a"
        });
        let Some(p) = http_post_json_with_headers(client, &url, &payload, &[]).await else {
            continue;
        };
        let bl = body_lower(&p.body);
        let policy_hint = bl.contains("length")
            || bl.contains("complexity")
            || bl.contains("uppercase")
            || bl.contains("special character")
            || bl.contains("too weak")
            || bl.contains("too short");
        if !policy_hint {
            continue;
        }
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Password policy oracle leaks requirements: {url}"),
                "low",
                MITRE_SPRAY,
                "Registration/signup endpoint reveals password-complexity rules in error text — helps attackers craft spray dictionaries that pass client-side and server-side policy in fewer attempts.",
                target,
                0.78,
                Evidence::new()
                    .with("url", url)
                    .with("http_status", p.status)
                    .check("policy_oracle", true, "complexity/length hints in body"),
            ),
            &[("category", json!("password_policy"))],
        ));
    }
    None
}

async fn probe_oidc_device_code(client: &Client, base: &str, target: &str) -> Option<Value> {
    const DISCOVERY: &[&str] = &[
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ];
    for path in DISCOVERY {
        let url = join_url(base, path);
        let Some(p) = http_get(client, &url).await else {
            continue;
        };
        if p.status != 200 {
            continue;
        }
        let doc: Value = serde_json::from_str(&p.body).ok()?;
        let grants = doc
            .get("grant_types_supported")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !grants.iter().any(|g| {
            g.contains("device_code") || g.contains("urn:ietf:params:oauth:grant-type:device-code")
        }) {
            continue;
        }
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                "OIDC device authorization grant enabled",
                "medium",
                MITRE_VALID,
                &format!(
                    "OIDC discovery at {url} advertises device_code grant — phishing-resistant auth bypass class; review whether device-code flow should be restricted."
                ),
                target,
                0.88,
                Evidence::new()
                    .with("discovery_url", url)
                    .with("grant_types_supported", json!(grants)),
            ),
            &[("category", json!("device_code"))],
        ));
    }
    None
}

async fn probe_basic_ntlm_surface(client: &Client, url: &str, target: &str) -> Option<Value> {
    let Some(p) = http_get(client, url).await else {
        return None;
    };
    let www = p
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    if !(www.contains("basic") || www.contains("ntlm") || www.contains("negotiate")) {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("HTTP auth spray surface (Basic/NTLM): {url}"),
            "medium",
            MITRE_SPRAY,
            &format!(
                "Endpoint advertises `{www}` — enables Basic/NTLM credential spray distinct from form/JSON login. Enforce lockout and MFA at the auth layer."
            ),
            target,
            0.87,
            Evidence::new()
                .with("url", url)
                .with("www_authenticate", www.clone())
                .check("http_auth", true, www),
        ),
        &[("category", json!("basic_ntlm"))],
    ))
}

async fn probe_browser_script_differential(
    client: &Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let user = "weissman_probe_waf";
    let pass = "WeissmanProbe!WAF";
    let payload = json!({"username": user, "password": pass});
    let script =
        http_post_json_with_headers(client, url, &payload, &[("User-Agent", "curl/8.0")]).await?;
    let browser = http_post_json_with_headers(
        client,
        url,
        &payload,
        &[(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        )],
    )
    .await?;
    let script_ok = matches!(script.status, 200 | 401 | 403) && script.status != 429;
    let browser_blocked = browser.status == 403 || browser.status == 429;
    if script_ok && browser_blocked {
        return Some(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("WAF/script bypass gap (stuffer-friendly): {url}"),
                "high",
                MITRE_SPRAY,
                &format!(
                    "Script User-Agent returned HTTP {} while browser UA returned {} — automated credential stuffing may bypass WAF rules that only inspect browser fingerprints.",
                    script.status, browser.status
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", url)
                    .with("script_status", script.status)
                    .with("browser_status", browser.status),
            ),
            &[("category", json!("browser_waf_gap"))],
        ));
    }
    None
}

async fn probe_breach_password_differential(
    client: &Client,
    url: &str,
    target: &str,
) -> Option<Value> {
    let user = "weissman_probe_breach";
    let breach = attempt_json_login(client, url, user, BREACH_PROBE_PASSWORD, &[]).await?;
    let random = attempt_json_login(client, url, user, RANDOM_PROBE_PASSWORD, &[]).await?;
    let bl_b = body_lower(&breach.body);
    let bl_r = body_lower(&random.body);
    let diff = breach.status != random.status
        || breach.body.len().abs_diff(random.body.len()) > 20
        || contains_any(&bl_b, ENUM_PASS_MARKERS) != contains_any(&bl_r, ENUM_PASS_MARKERS)
        || contains_any(&bl_b, ENUM_USER_MARKERS) != contains_any(&bl_r, ENUM_USER_MARKERS);
    if !diff {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Breach-password differential oracle: {url}"),
            "medium",
            MITRE_STUFF,
            "Common breach-password vs high-entropy probe produced distinct responses — attackers can tune spray lists toward likely passwords with fewer wasted attempts.",
            target,
            0.8,
            Evidence::new()
                .with("url", url)
                .with("breach_status", breach.status)
                .with("random_status", random.status)
                .check("differential", true, "distinct status/body/error"),
        ),
        &[("category", json!("breach_differential"))],
    ))
}

async fn probe_timing_user_enum(
    client: &Client,
    url: &str,
    samples: usize,
    target: &str,
) -> Option<Value> {
    let pass = "WeissmanProbe!Invalid";
    let mut a = Vec::new();
    let mut b = Vec::new();
    for _ in 0..samples {
        let t0 = Instant::now();
        let _ = attempt_json_login(client, url, "weissman_probe_timing_a", pass, &[]).await;
        a.push(t0.elapsed().as_millis() as u64);
        let t1 = Instant::now();
        let _ = attempt_json_login(
            client,
            url,
            "weissman_probe_timing_xyz_nonexistent",
            pass,
            &[],
        )
        .await;
        b.push(t1.elapsed().as_millis() as u64);
    }
    let ma = a.iter().sum::<u64>() as f64 / a.len() as f64;
    let mb = b.iter().sum::<u64>() as f64 / b.len() as f64;
    let delta = (ma - mb).abs();
    if delta < 40.0 || delta < ma.max(mb) * 0.15 {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Timing user-enumeration oracle ({delta:.0}ms Δ): {url}"),
            "high",
            MITRE_STUFF,
            &format!(
                "Microsecond-scale timing differential between probe usernames ({ma:.0}ms vs {mb:.0}ms over {samples} samples) — constant-time auth compare may be absent."
            ),
            target,
            0.83,
            Evidence::new()
                .with("url", url)
                .with("mean_ms_a", ma)
                .with("mean_ms_b", mb)
                .with("delta_ms", delta)
                .with("samples", samples),
        ),
        &[("category", json!("timing_enumeration"))],
    ))
}

async fn probe_entra_aadsts(client: &Client, domain: &str, target: &str) -> Option<Value> {
    let url = format!("https://login.microsoftonline.com/{domain}/oauth2/v2.0/token");
    let form = [
        ("grant_type", "password"),
        ("client_id", "1b730954-1685-4ba8-b908-6d8971dc1eab"),
        ("username", &format!("weissman_probe@{domain}")),
        ("password", "WeissmanProbe!Invalid"),
        ("scope", "openid"),
    ];
    let resp = client.post(&url).form(&form).send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if body.is_empty() {
        return None;
    }
    let bl = body.to_ascii_lowercase();
    let user_exists = AADSTS_USER_EXISTS
        .iter()
        .any(|c| bl.contains(&c.to_ascii_lowercase()));
    let user_missing = AADSTS_USER_MISSING
        .iter()
        .any(|c| bl.contains(&c.to_ascii_lowercase()));
    let locked = AADSTS_LOCKOUT
        .iter()
        .any(|c| bl.contains(&c.to_ascii_lowercase()));
    let code = AADSTS_USER_EXISTS
        .iter()
        .chain(AADSTS_USER_MISSING.iter())
        .chain(AADSTS_LOCKOUT.iter())
        .find(|c| bl.contains(&c.to_ascii_lowercase()))
        .map(|s| (*s).to_string());
    let severity = if locked {
        "info"
    } else if user_exists && !user_missing {
        "high"
    } else if user_missing {
        "medium"
    } else {
        "low"
    };
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "Entra token endpoint live AADSTS signal{}",
                code.as_ref().map(|c| format!(" ({c})")).unwrap_or_default()
            ),
            severity,
            MITRE_STUFF,
            "Live ROPC-shaped probe against login.microsoftonline.com returned Microsoft AADSTS error taxonomy — reveals smart-lockout, MFA-required, and user-existence classes without guessing the primary app login URL.",
            target,
            0.94,
            Evidence::new()
                .with("token_url", url)
                .with("http_status", status)
                .with("aadsts_code", code.unwrap_or_default())
                .check("user_exists_class", user_exists, "50126/50055/50076 class")
                .check("user_missing_class", user_missing, "50034 class")
                .check("lockout_class", locked, "50053 class")
                .raw_excerpt(body.as_bytes()),
        ),
        &[("category", json!("entra_aadsts"))],
    ))
}

async fn probe_cors_login_api(client: &Client, url: &str, target: &str) -> Option<Value> {
    let resp = client
        .post(url)
        .header("Origin", "https://evil.weissman.invalid")
        .header("Access-Control-Request-Method", "POST")
        .header("Content-Type", "application/json")
        .body(r#"{"username":"x","password":"y"}"#)
        .send()
        .await
        .ok()?;
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if acao != "*" && !acao.contains("evil.weissman.invalid") {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Permissive CORS on login API: {url}"),
            "medium",
            MITRE_STUFF,
            &format!(
                "Login endpoint reflects `Access-Control-Allow-Origin: {acao}` — browser-based credential stuffing from an attacker origin may be possible."
            ),
            target,
            0.86,
            Evidence::new()
                .with("url", url)
                .with("acao", acao),
        ),
        &[("category", json!("cors_login"))],
    ))
}

async fn probe_lockout_decay(
    client: &Client,
    surface: &LoginSurface,
    spray: &SprayOutcome,
    cfg: &ScanConfig,
    extra: &[(&str, &str)],
    target: &str,
) -> Option<Value> {
    if !spray.locked && !spray.rate_limited {
        return None;
    }
    sleep(Duration::from_millis(cfg.lockout_decay_ms)).await;
    let r = attempt_json_login(
        client,
        &surface.url,
        "weissman_probe_decay",
        "WeissmanProbe!Decay",
        extra,
    )
    .await?;
    if r.status == 429 || r.status == 423 || contains_any(&body_lower(&r.body), LOCKOUT_MARKERS) {
        return None;
    }
    Some(with_fields(
        finding_rich(
            ENGINE_ID,
            &format!(
                "Short lockout decay (~{}s): {}",
                cfg.lockout_decay_ms / 1000,
                surface.url
            ),
            "high",
            MITRE_SPRAY,
            "After triggering lockout/rate-limit, a subsequent attempt succeeded within the configured decay window — attackers can resume spray with short cool-downs.",
            target,
            0.88,
            Evidence::new()
                .with("url", surface.url.clone())
                .with("decay_ms", cfg.lockout_decay_ms)
                .with("post_decay_status", r.status),
        ),
        &[("category", json!("lockout_decay"))],
    ))
}

fn build_remediation_playbook(posture: &SprayPosture, host: &str) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    if !posture.no_rate_limit.is_empty() {
        actions.push(json!({
            "priority": "P0",
            "control": "Rate limiting",
            "action": "Enforce per-IP AND per-username throttling with HTTP 429 on login/token endpoints; align CDN/WAF with origin counters.",
            "cis": "CIS 6.5",
        }));
    }
    if !posture.user_enum.is_empty() || !posture.timing_enum_surfaces.is_empty() {
        actions.push(json!({
            "priority": "P0",
            "control": "Anti-enumeration",
            "action": "Normalize auth failure responses (status, body, timing); remove AADSTS50034 vs 50126 distinctions at the app edge.",
            "cis": "CIS 5.2",
        }));
    }
    if !posture.ropc_enabled.is_empty() {
        actions.push(json!({
            "priority": "P0",
            "control": "OIDC ROPC",
            "action": "Disable resource-owner password credentials grant; migrate to auth-code + PKCE.",
            "cis": "NIST 800-63B",
        }));
    }
    if !posture.mfa_absent.is_empty() {
        actions.push(json!({
            "priority": "P1",
            "control": "MFA",
            "action": "Require phishing-resistant MFA (FIDO2/WHfB) on all spray-viable surfaces including federated IdP.",
            "cis": "CIS 5.3",
        }));
    }
    if !posture.xff_bypassable.is_empty() || !posture.browser_waf_gaps.is_empty() {
        actions.push(json!({
            "priority": "P1",
            "control": "Automation resistance",
            "action": "Rate-limit on account identity not client IP alone; block script UAs on auth unless API clients are registered.",
            "cis": "CIS 13.10",
        }));
    }
    with_fields(
        finding_rich(
            ENGINE_ID,
            &format!("Remediation playbook — {host} ({} actions)", actions.len()),
            "info",
            MITRE_SPRAY,
            "Prioritized remediation sequence synthesized from observed spray/stuffing gaps — ordered for maximum reduction in credential-attack blast radius.",
            host,
            1.0,
            Evidence::new()
                .with("actions", json!(actions))
                .with("radar", posture.radar()),
        ),
        &[("category", json!("remediation_playbook"))],
    )
}

// ── Entry points ────────────────────────────────────────────────────────────────

pub async fn run_password_spray_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let host = extract_host(&base);
    let cfg = ScanConfig::load(&ArsenalConfig::from_ctx(ctx), &host);
    let client = build_client(cfg.timeout_ms);

    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(ref h) = cfg.auth_header {
        extra.extend(parse_auth_header(h));
    }
    if let Some(ref c) = cfg.cookies {
        extra.push(("Cookie", c.as_str()));
    }

    let mut paths: Vec<String> = cfg.paths.clone();
    for p in ctx.discovered_paths.iter().take(12) {
        let p = p.trim();
        if !p.is_empty() && !paths.iter().any(|x| x == p) {
            paths.push(p.to_string());
        }
    }
    let path_cap = match cfg.intensity {
        Intensity::Light => 12,
        Intensity::Normal => 24,
        Intensity::Aggressive => paths.len().min(40),
    };
    paths.truncate(path_cap);

    let mut findings: Vec<Value> = Vec::new();
    let mut posture = SprayPosture::default();
    let mut seen_urls: BTreeSet<String> = BTreeSet::new();

    let intel_domain = if cfg.domain.contains('.') {
        cfg.domain.clone()
    } else {
        host.clone()
    };

    if cfg.check_m365_realm {
        if let Some(f) = probe_m365_user_realm(&client, &intel_domain, target).await {
            if f.get("category") == Some(&json!("m365_realm")) {
                let federated = f["evidence"]["namespace_type"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case("Federated"))
                    .unwrap_or(false);
                posture.m365_federated = federated;
            }
            findings.push(f);
        }
    }
    if cfg.check_autodiscover {
        if let Some(f) = probe_exchange_autodiscover(&client, &intel_domain, target).await {
            findings.push(f);
        }
    }
    if cfg.check_oidc_ropc {
        if let Some(f) = probe_oidc_ropc(&client, &base, target).await {
            posture.ropc_enabled.push(base.clone());
            findings.push(f);
        }
    }
    if cfg.check_saml_metadata {
        if let Some(f) = probe_saml_metadata(&client, &base, target).await {
            posture.saml_exposed.push(base.clone());
            findings.push(f);
        }
    }
    if cfg.check_password_policy {
        if let Some(f) = probe_password_policy_oracle(&client, &base, target).await {
            findings.push(f);
        }
    }
    if cfg.check_device_code {
        if let Some(f) = probe_oidc_device_code(&client, &base, target).await {
            posture.device_code_enabled.push(base.clone());
            findings.push(f);
        }
    }
    if cfg.check_entra_errors {
        if let Some(f) = probe_entra_aadsts(&client, &intel_domain, target).await {
            posture.entra_signals.push(intel_domain.clone());
            findings.push(f);
        }
    }
    if cfg.check_subdomain_login {
        let subs = hunt_subdomain_logins(
            &client,
            &intel_domain,
            &cfg.subdomain_prefixes,
            target,
            cfg.concurrency,
        )
        .await;
        for f in subs {
            if let Some(url) = f
                .get("evidence")
                .and_then(|e| e.get("url"))
                .and_then(Value::as_str)
            {
                posture.subdomain_logins.push(url.to_string());
            }
            findings.push(f);
        }
    }

    let surfaces: Vec<LoginSurface> = stream::iter(paths.clone())
        .map(|path| {
            let client = client.clone();
            let base = base.clone();
            let cfg = cfg.clone();
            let extra = extra.clone();
            async move { discover_surface(&client, &base, &path, &cfg, &extra).await }
        })
        .buffer_unordered(cfg.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let spray_cap = match cfg.intensity {
        Intensity::Light => 2,
        Intensity::Normal => 4,
        Intensity::Aggressive => 8,
    };

    for surface in surfaces {
        if !seen_urls.insert(surface.url.clone()) {
            continue;
        }
        let spray = if cfg.dry_run {
            SprayOutcome::default()
        } else {
            run_spray_simulation(&client, &surface, &cfg, &extra).await
        };
        findings.extend(surface_findings(
            target,
            &surface,
            &spray,
            &cfg,
            &mut posture,
        ));

        if cfg.check_user_enum && !cfg.dry_run {
            if let Some((kind, ev)) =
                probe_user_enumeration(&client, &surface.url, &cfg, &extra).await
            {
                posture.user_enum.push(surface.url.clone());
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("User-enumeration oracle: {}", surface.url),
                        "high",
                        MITRE_STUFF,
                        "Distinct HTTP status, body length, or error messaging between probe usernames — attackers can harvest valid accounts before spraying.",
                        target,
                        0.86,
                        ev,
                    ),
                    &[("category", json!(kind))],
                ));
            }
        }
        if !cfg.dry_run && spray.attempts > 0 {
            // Re-fetch one attempt body marker for verbose credential errors (informational for posture).
            if let Some(r) = attempt_json_login(
                &client,
                &surface.url,
                "weissman_probe_verbose",
                "invalid",
                &extra,
            )
            .await
            {
                let bl = body_lower(&r.body);
                if contains_any(&bl, ENUM_USER_MARKERS) {
                    posture.verbose_errors.push(surface.url.clone());
                }
            }
        }
        if cfg.check_lockout_curve && !cfg.dry_run {
            if let Some(f) = lockout_curve_finding(target, &surface, &spray) {
                if let Some(at) = spray.lockout_at.or(spray.first_429_at) {
                    posture.lockout_curves.push((surface.url.clone(), at));
                }
                findings.push(f);
            }
        }
        if cfg.check_xff_bypass && !cfg.dry_run && !spray.rate_limited {
            if let Some(f) =
                probe_xff_rate_limit_surface(&client, &surface, &cfg, &extra, target).await
            {
                posture.xff_bypassable.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_oidc_ropc && surface.auth_type == "oauth_federation" {
            if let Some(f) = probe_oidc_ropc(&client, &surface.url, target).await {
                posture.ropc_enabled.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_saml_metadata && surface.federated {
            if let Some(f) = probe_saml_metadata(&client, &surface.url, target).await {
                posture.saml_exposed.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_basic_ntlm {
            if let Some(f) = probe_basic_ntlm_surface(&client, &surface.url, target).await {
                posture.basic_auth_surfaces.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_browser_differential && !cfg.dry_run {
            if let Some(f) = probe_browser_script_differential(&client, &surface.url, target).await
            {
                posture.browser_waf_gaps.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_breach_differential && !cfg.dry_run {
            if let Some(f) = probe_breach_password_differential(&client, &surface.url, target).await
            {
                posture.breach_oracles.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_timing_enum && !cfg.dry_run {
            if let Some(f) =
                probe_timing_user_enum(&client, &surface.url, cfg.timing_samples, target).await
            {
                posture.timing_enum_surfaces.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_cors_login {
            if let Some(f) = probe_cors_login_api(&client, &surface.url, target).await {
                posture.cors_permissive.push(surface.url.clone());
                findings.push(f);
            }
        }
        if cfg.check_lockout_decay && !cfg.dry_run {
            if let Some(f) =
                probe_lockout_decay(&client, &surface, &spray, &cfg, &extra, target).await
            {
                posture.short_lockout_decay.push(surface.url.clone());
                findings.push(f);
            }
        }
        if findings.len() >= spray_cap * 8 {
            break;
        }
    }

    if findings.is_empty() && cfg.include_info {
        if let Some(p) = http_get(&client, &base).await {
            let bl = body_lower(&p.body);
            if bl.contains("login") || bl.contains("sign in") {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "Login UI referenced but no standard path resolved",
                    "info",
                    MITRE_SPRAY,
                    "The landing page references authentication but none of the default login paths responded. Supply exact paths via the `paths` parameter.",
                    target,
                    0.5,
                    Evidence::new().with("url", base.clone()).check("login_hint", true, "page references login"),
                ));
            }
        }
    }

    if cfg.attack_paths && posture.has_any() {
        findings.extend(synthesize_attack_paths(target, &posture, &host));
    }

    supreme::run_transport_probes(
        &client,
        &base,
        &mut posture,
        &mut findings,
        target,
        cfg.check_hsts_auth,
        cfg.check_webauthn_surface,
        cfg.check_oidc_pkce,
        cfg.check_cookie_security,
    )
    .await;

    let category_scores = supreme::finalize_category_scores(&posture);

    if cfg.posture_score && (!posture.login_surfaces.is_empty() || posture.has_any()) {
        let score = posture.score();
        let grade = SprayPosture::grade(score);
        let friction = posture.stuffing_friction();
        let radar = posture.radar();
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Credential-Stuffing Posture: {}/100 (Grade {})", score, grade),
                "info",
                MITRE_SPRAY,
                &format!(
                    "Quantified password-spray / stuffing hygiene for {host} from {} login surface(s) + {} subdomain(s). \
                     Stuffing friction {:.0}%. Six-axis radar + 8-domain category scores emitted.",
                    posture.login_surfaces.len(),
                    posture.subdomain_logins.len(),
                    friction * 100.0
                ),
                target,
                1.0,
                Evidence::new()
                    .with("score", score)
                    .with("grade", grade)
                    .with("stuffing_friction", friction)
                    .with("posture_radar", radar.clone())
                    .with("category_scores", category_scores.to_json())
                    .with("surfaces", posture.login_surfaces.len())
                    .with("subdomain_logins", json!(posture.subdomain_logins))
                    .with("no_rate_limit", json!(posture.no_rate_limit))
                    .with("user_enum", json!(posture.user_enum))
                    .with("ropc_enabled", json!(posture.ropc_enabled))
                    .with("xff_bypassable", json!(posture.xff_bypassable))
                    .with("lockout_curves", json!(posture.lockout_curves))
                    .with("entra_signals", json!(posture.entra_signals))
                    .with("dry_run", cfg.dry_run),
            ),
            &[
                ("category", json!("posture_score")),
                ("score", json!(score)),
                ("grade", json!(grade)),
                ("posture_radar", radar),
            ],
        ));
    }

    if cfg.check_remediation_playbook && posture.has_any() {
        findings.push(build_remediation_playbook(&posture, &host));
    }

    if cfg.attack_paths && posture.has_any() {
        supreme::extend_attack_paths(target, &posture, &host, &mut findings);
    }
    supreme::emit_toxic_headline(target, &posture, &mut findings);
    supreme::emit_remediation_roadmap(target, &posture, &mut findings);
    if cfg.emit_agent_guidance {
        supreme::emit_agent_guidance(target, &mut findings);
    }

    let (graph_nodes, graph_edges) = supreme::build_security_graph(target, &posture, &host);

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    let path_count = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("attack_path"))
        .count();
    let summary = format!(
        "password_spray: {} finding(s) on {host} · {} surface(s) · posture {}/100 (Grade {}){}{}{}{}",
        findings.len(),
        posture.login_surfaces.len(),
        posture.score(),
        SprayPosture::grade(posture.score()),
        if cfg.dry_run { " · dry-run" } else { "" },
        if toxic > 0 {
            format!(", {toxic} toxic combo(s)")
        } else {
            String::new()
        },
        if path_count > 0 {
            format!(", {path_count} attack path(s)")
        } else {
            String::new()
        },
        if !category_scores.to_json().is_null() {
            " · 8-domain scores".to_string()
        } else {
            String::new()
        },
    );
    EngineResult::ok_with_graph(findings, summary, graph_nodes, graph_edges)
}

/// Backward-compatible entry (default parameters) — used by alias engines + the CLI wrapper.
pub async fn run_password_spray_result(target: &str) -> EngineResult {
    run_password_spray_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_password_spray(target: &str) {
    print_result(run_password_spray_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_penalizes_gaps() {
        let mut p = SprayPosture::default();
        assert_eq!(p.score(), 100);
        p.no_rate_limit.push("https://x/login".into());
        p.user_enum.push("https://x/login".into());
        assert!(p.score() < 70);
        assert!(p.has_any());
    }

    #[test]
    fn grade_ladder() {
        assert_eq!(SprayPosture::grade(100), "A+");
        assert_eq!(SprayPosture::grade(65), "D");
        assert_eq!(SprayPosture::grade(40), "F");
    }

    #[test]
    fn detects_lockout_marker() {
        let r = HttpResp {
            status: 200,
            body: "Too many failed attempts, try again later".into(),
            headers: vec![],
        };
        let o = analyze_attempt(&r, 3);
        assert!(o.locked);
    }

    #[test]
    fn federated_path_fingerprint() {
        let (t, fed) = fingerprint_auth_type("/adfs/oauth2/authorize", 302, "", &[]);
        assert_eq!(t, "oauth_federation");
        assert!(fed);
    }

    #[test]
    fn wordlist_sizes() {
        let c = ScanConfig::load(
            &ArsenalConfig::from_value(json!({ "wordlist": "large" })),
            "example.com",
        );
        assert!(c.usernames.len() >= LARGE_USERS.len());
        assert!(c.passwords.len() >= LARGE_PASSWORDS.len());
    }

    #[test]
    fn radar_axes_in_range() {
        let mut p = SprayPosture::default();
        p.no_rate_limit.push("x".into());
        let r = p.radar();
        assert!(r["rate_limit"].as_u64().unwrap_or(0) < 100);
        assert_eq!(r["lockout"].as_u64().unwrap_or(0), 100);
    }

    #[test]
    fn stuffing_friction_rises_with_controls() {
        let mut p = SprayPosture::default();
        assert!(p.stuffing_friction() < 0.6);
        p.no_rate_limit.push("x".into());
        p.no_lockout.push("x".into());
        assert!(p.stuffing_friction() > 0.4);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_password_spray_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
