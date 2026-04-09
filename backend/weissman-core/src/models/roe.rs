//! Rules of engagement (client config).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(description = "Rules of engagement mode for scan safety")]
pub enum RoeMode {
    #[default]
    SafeProofs,
    WeaponizedGodMode,
}

impl RoeMode {
    #[must_use]
    pub fn from_config_str(s: &str) -> Self {
        match s.trim() {
            "weaponized_god_mode" => Self::WeaponizedGodMode,
            _ => Self::SafeProofs,
        }
    }
}
