//! CNAPP Layer 4: Deception engine. Generates honeytokens dynamically (no hardcoded values).
//! Format and type derived from client tech/config. Trigger ingestion records attacker fingerprint.

use rand::Rng;

/// Asset types for deception (format generated from type).
pub const TYPE_AWS_KEY: &str = "aws_key";
pub const TYPE_DB_CRED: &str = "db_cred";
pub const TYPE_API_KEY: &str = "api_key";
pub const TYPE_SHADOW_ENDPOINT: &str = "shadow_endpoint";

fn rand_hex(len: usize) -> String {
    let mut s = String::with_capacity(len);
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        s.push_str(&format!("{:x}", rng.gen_range(0..16)));
    }
    s
}

fn rand_alpha(len: usize) -> String {
    let mut s = String::with_capacity(len);
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        let c = rng.gen_range(0..26);
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
