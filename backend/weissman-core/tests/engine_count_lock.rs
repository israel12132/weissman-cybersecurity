//! Customer-facing engine-count lock: the catalog advertised on login is the
//! production registry, not a leftover marketing number (the retired 254 headline).

use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

const CUSTOMER_ENGINE_COUNT: usize = 573;

#[test]
fn production_registry_is_exactly_the_customer_engine_count() {
    assert_eq!(
        PRODUCTION_ENGINE_IDS.len(),
        CUSTOMER_ENGINE_COUNT,
        "PRODUCTION_ENGINE_IDS drifted from the advertised fleet size"
    );
    let unique: std::collections::HashSet<&str> = PRODUCTION_ENGINE_IDS.iter().copied().collect();
    assert_eq!(
        unique.len(),
        CUSTOMER_ENGINE_COUNT,
        "duplicate production engine ids would inflate the login headline"
    );
    assert!(
        !PRODUCTION_ENGINE_IDS.iter().any(|id| id.is_empty()),
        "empty engine id in production registry"
    );
}

#[test]
fn ot_engines_stay_in_the_production_catalog() {
    for id in [
        "smart_grid_dlms_attack",
        "ot_sis_triton_attack",
        "building_automation_attack",
        "avionics_adsb_attack",
    ] {
        assert!(
            PRODUCTION_ENGINE_IDS.contains(&id),
            "{id} must remain a production engine so RoE can block it instead of silently dropping it"
        );
    }
}
