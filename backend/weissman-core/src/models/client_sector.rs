//! Client industry/sector classification.
//!
//! The sector drives which compliance frameworks a client is measured against
//! (IEC 62443 for energy, HIPAA for healthcare, PCI for finance, …), so the
//! stored value has to come from a closed set rather than free text.
//!
//! Kept here so the HTTP handlers, the frontend catalog
//! (`ClientOnboardingWizard`), and the `clients.sector` column comment all
//! agree on one list.

/// Canonical sector identifiers, in the order the onboarding wizard renders them.
pub const CLIENT_SECTORS: &[&str] = &[
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

/// Empty string is the stored representation of "unclassified" — it matches the
/// `NOT NULL DEFAULT ''` column so existing clients need no backfill.
pub const CLIENT_SECTOR_UNCLASSIFIED: &str = "";

/// `true` when `value` is a canonical sector or the unclassified sentinel.
pub fn is_valid_client_sector(value: &str) -> bool {
    value == CLIENT_SECTOR_UNCLASSIFIED || CLIENT_SECTORS.contains(&value)
}

/// Normalize caller input to the stored form: trimmed and lowercased.
///
/// Returns `Err` with the offending value when it is not a known sector, so the
/// API can reject it instead of silently persisting an unusable classification.
pub fn normalize_client_sector(value: &str) -> Result<&str, &str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(CLIENT_SECTOR_UNCLASSIFIED);
    }
    CLIENT_SECTORS
        .iter()
        .find(|s| s.eq_ignore_ascii_case(trimmed))
        .copied()
        .ok_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_eleven_unique_sectors() {
        assert_eq!(CLIENT_SECTORS.len(), 11);
        let mut sorted = CLIENT_SECTORS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CLIENT_SECTORS.len());
    }

    #[test]
    fn unclassified_and_known_sectors_are_valid() {
        assert!(is_valid_client_sector(""));
        for s in CLIENT_SECTORS {
            assert!(is_valid_client_sector(s), "{s} should be valid");
        }
    }

    #[test]
    fn unknown_sector_is_rejected() {
        assert!(!is_valid_client_sector("banking"));
        assert_eq!(normalize_client_sector("banking"), Err("banking"));
    }

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(normalize_client_sector("  Energy "), Ok("energy"));
        assert_eq!(normalize_client_sector("GOVERNMENT"), Ok("government"));
        assert_eq!(normalize_client_sector("   "), Ok(""));
    }
}
