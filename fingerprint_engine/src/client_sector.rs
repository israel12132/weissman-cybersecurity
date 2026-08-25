//! Allowed `clients.sector` values.
//!
//! Must stay aligned with:
//! - `crates/weissman-db/migrations/20260818120000_clients_sector.sql`
//! - `frontend/src/components/clients/ClientOnboardingWizard.jsx`

/// Industry classification stored on `clients.sector`. Empty string = unclassified.
pub const ALLOWED_CLIENT_SECTORS: &[&str] = &[
    "government",
    "energy",
    "healthcare",
    "finance",
    "technology",
    "manufacturing",
    "retail",
    "education",
    "defense",
    "telecom",
    "other",
];

/// Normalize a client sector from the API body. Empty / whitespace → unclassified (`""`).
/// Unknown values are rejected so the column stays enumerable for compliance routing.
pub fn normalize_client_sector(raw: Option<&str>) -> Result<String, String> {
    let s = raw.unwrap_or("").trim().to_ascii_lowercase();
    if s.is_empty() {
        return Ok(String::new());
    }
    if ALLOWED_CLIENT_SECTORS.iter().any(|allowed| *allowed == s) {
        Ok(s)
    } else {
        Err(format!(
            "invalid sector {s:?}; expected empty or one of: {}",
            ALLOWED_CLIENT_SECTORS.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_are_unclassified() {
        assert_eq!(normalize_client_sector(None).unwrap(), "");
        assert_eq!(normalize_client_sector(Some("  ")).unwrap(), "");
    }

    #[test]
    fn known_sectors_normalize_case() {
        assert_eq!(
            normalize_client_sector(Some("Healthcare")).unwrap(),
            "healthcare"
        );
        assert_eq!(
            normalize_client_sector(Some("GOVERNMENT")).unwrap(),
            "government"
        );
    }

    #[test]
    fn unknown_sector_is_rejected() {
        assert!(normalize_client_sector(Some("space-force")).is_err());
    }
}
