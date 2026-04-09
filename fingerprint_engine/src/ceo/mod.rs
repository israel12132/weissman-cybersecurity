//! CEO Command Center: DB-backed Genesis strategy, war-room telemetry, HPC policy, vaccine vault API.

pub mod god_mode;
pub mod hpc;
pub mod ops_status;
pub mod safe_mode;
pub mod sovereign;
pub mod strategy;
pub mod vault;
pub mod war_room;

pub use hpc::{get_hpc_policy, put_hpc_policy, HpcPolicyRow, HpcPolicyView};
pub use sovereign::{
    enqueue_sovereign_from_buffer_row, list_sovereign_buffer, SovereignBufferRowOut,
};
pub use strategy::{
    get_ceo_strategy_json, load_env_fallback, load_genesis_runtime_params, patch_ceo_strategy,
    GenesisRuntimeParams, STRATEGY_KEYS,
};
pub use vault::{
    export_vault_criticals_csv, get_suspended_graph, get_vault_row, list_suspended_graphs,
    list_vault_rows, match_vault_row, post_resume_suspended_job, post_vault_row, VaultInsertBody,
};
pub use war_room::{
    insert_war_room_event, sse_war_room_stream, WarRoomContext, WarRoomMirror,
};

pub mod tenant_engines;
pub use tenant_engines::{default_tenant_id, patch_tenant_active_engine};
