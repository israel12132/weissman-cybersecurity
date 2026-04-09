//! OSINT — implemented in `weissman-engines` (`CyberEngine`: [`weissman_engines::osint::OsintCyberEngine`]).

use crate::engine_result::EngineResult;
use crate::stealth_engine;

pub use weissman_engines::osint::{run_osint, subdomains_from_osint_findings};

pub async fn run_osint_result(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    weissman_engines::osint::run_osint_result(target, stealth)
        .await
        .into()
}
