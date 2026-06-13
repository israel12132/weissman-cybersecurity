//! Reserved for full timestomping detection.
//!
//! Production-grade timestomp detection requires raw filesystem reads (NTFS $STANDARD_INFORMATION
//! vs $FILE_NAME). We expose this as an `agent_required` capability today, returning a stub when
//! invoked so callers know the agent received the request.

#![allow(dead_code)]

use super::finding;
use serde_json::Value;

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    Ok(vec![finding(
        engine,
        "Timestomp detection requires raw filesystem driver",
        "info",
        "T1070.006",
        "The agent is collecting standard `stat()` metadata. Full timestomp detection compares NTFS $SI vs $FN streams, which the current cross-platform agent doesn't read. Planned for the kernel module add-on.",
        serde_json::Map::new(),
    )])
}
