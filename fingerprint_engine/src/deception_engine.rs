//! CNAPP Layer 4: Deception engine. Generates honeytokens dynamically (no hardcoded values).
//! Format and type derived from client tech/config. Trigger ingestion records attacker fingerprint.

use rand::RngExt;

/// Asset types for deception (format generated from type).
pub const TYPE_AWS_KEY: &str = "aws_key";
pub const TYPE_DB_CRED: &str = "db_cred";
pub const TYPE_API_KEY: &str = "api_key";
pub const TYPE_SHADOW_ENDPOINT: &str = "shadow_endpoint";

fn rand_hex(len: usize) -> String {
    let mut s = String::with_capacity(len);
    let mut rng = rand::rng();
    for _ in 0..len {
        s.push_str(&format!("{:x}", rng.random_range(0..16)));
    }
    s
}

fn rand_alpha(len: usize) -> String {
    let mut s = String::with_capacity(len);
    let mut rng = rand::rng();
    for _ in 0..len {
        let c = rng.random_range(0..26);
        s.push((b'A' + c) as char);
    }
    s
}

/// Generate a single honeytoken value. Format derived from asset_type (no hardcoded examples).
pub fn generate_honeytoken(asset_type: &str, _tech_hint: &str) -> (String, String) {
    let (value, location) = match asset_type {
        TYPE_AWS_KEY => {
            let key = format!("AKIA{}", rand_alpha(16));
            let secret = rand_hex(40);
            (format!("{}:{}", key, secret), "env:AWS_ACCESS_KEY_ID")
        }
        TYPE_DB_CRED => {
            let user = format!("db_honey_{}", rand_hex(8));
            let pass = rand_hex(24);
            (format!("{}:{}", user, pass), "config:database.url")
        }
        TYPE_API_KEY => {
            let key = format!("sk_live_{}", rand_hex(32));
            (key, "env:API_KEY")
        }
        TYPE_SHADOW_ENDPOINT => {
            let path = format!("/.well-known/{}", rand_hex(12));
            (path, "route:shadow")
        }
        _ => (rand_hex(24), "unknown"),
    };
    (value, location.to_string())
}

/// (client_id, asset_type, token_value, deployment_location)
pub type DeceptionAssetRecord = (String, String, String, String);

/// Generate multiple honeytokens for a client. Types derived from requested types (from config/UI).
pub fn generate_deception_assets(
    client_id: &str,
    types: &[String],
    tech_hint: &str,
) -> Vec<DeceptionAssetRecord> {
    let mut out = Vec::new();
    for t in types {
        let (value, location) = generate_honeytoken(t, tech_hint);
        out.push((client_id.to_string(), t.clone(), value, location));
    }
    out
}

pub fn generate_deception_assets_simple(
    client_id: &str,
    tech_hint: &str,
) -> Vec<DeceptionAssetRecord> {
    let types = vec![
        TYPE_API_KEY.to_string(),
        TYPE_AWS_KEY.to_string(),
        TYPE_DB_CRED.to_string(),
    ];
    let mut out = Vec::new();
    for t in types {
        let (value, location) = generate_honeytoken(&t, tech_hint);
        out.push((client_id.to_string(), t, value, location));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_hex_has_correct_len_and_charset() {
        let s = rand_hex(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn rand_alpha_has_correct_len_and_uppercase() {
        let s = rand_alpha(16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn honeytoken_aws_key_format() {
        let (value, location) = generate_honeytoken(TYPE_AWS_KEY, "");
        assert_eq!(location, "env:AWS_ACCESS_KEY_ID");
        let parts: Vec<&str> = value.split(':').collect();
        assert_eq!(parts.len(), 2);
        // "AKIA" + 16 alpha = 20 chars
        assert!(parts[0].starts_with("AKIA"));
        assert_eq!(parts[0].len(), 20);
        // secret is 40 hex chars
        assert_eq!(parts[1].len(), 40);
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn honeytoken_db_cred_format() {
        let (value, location) = generate_honeytoken(TYPE_DB_CRED, "postgres");
        assert_eq!(location, "config:database.url");
        assert!(value.starts_with("db_honey_"));
        let parts: Vec<&str> = value.split(':').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn honeytoken_api_key_format() {
        let (value, location) = generate_honeytoken(TYPE_API_KEY, "");
        assert_eq!(location, "env:API_KEY");
        assert!(value.starts_with("sk_live_"));
        // "sk_live_" (8) + 32 hex = 40
        assert_eq!(value.len(), 40);
    }

    #[test]
    fn honeytoken_shadow_endpoint_format() {
        let (value, location) = generate_honeytoken(TYPE_SHADOW_ENDPOINT, "");
        assert_eq!(location, "route:shadow");
        assert!(value.starts_with("/.well-known/"));
    }

    #[test]
    fn honeytoken_unknown_type_falls_back() {
        let (value, location) = generate_honeytoken("something_else", "");
        assert_eq!(location, "unknown");
        assert_eq!(value.len(), 24);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_assets_preserves_client_and_type_order() {
        let types = vec![TYPE_API_KEY.to_string(), TYPE_DB_CRED.to_string()];
        let recs = generate_deception_assets("client-42", &types, "hint");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].0, "client-42");
        assert_eq!(recs[0].1, TYPE_API_KEY);
        assert_eq!(recs[1].1, TYPE_DB_CRED);
    }

    #[test]
    fn generate_assets_empty_types_yields_empty() {
        let recs = generate_deception_assets("c", &[], "hint");
        assert!(recs.is_empty());
    }

    #[test]
    fn generate_assets_simple_has_three_expected_types() {
        let recs = generate_deception_assets_simple("c1", "hint");
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].1, TYPE_API_KEY);
        assert_eq!(recs[1].1, TYPE_AWS_KEY);
        assert_eq!(recs[2].1, TYPE_DB_CRED);
        assert!(recs.iter().all(|r| r.0 == "c1"));
    }
}
