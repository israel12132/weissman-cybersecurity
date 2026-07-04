/**
 * Capability-based Engine UI manifest types (strict interface enforcement).
 * @module engineC2/types
 */

/**
 * @typedef {Object} EngineUiCapabilities
 * @property {boolean} [requires_target_input]
 * @property {boolean} [requires_ast_viewer]
 * @property {boolean} [requires_template_runner]
 * @property {boolean} [needs_memory_telemetry]
 * @property {boolean} [needs_live_telemetry]
 * @property {boolean} [requires_kill_switch]
 * @property {boolean} [requires_agent_gate]
 * @property {boolean} [requires_scan_dispatch]
 * @property {boolean} [requires_payload_tuning]
 * @property {number} [max_ast_nodes]
 */

/**
 * @typedef {Object} EngineUiChrome
 * @property {string} [badge_color]
 */

/**
 * @typedef {Object} EngineUiManifest
 * @property {string} engine_id
 * @property {string[]} route_paths
 * @property {string|null} [evidence_i18n_key]
 * @property {EngineUiCapabilities} capabilities
 * @property {EngineUiChrome} chrome
 */

/**
 * @typedef {Object} EngineManifestEnvelope
 * @property {number} version
 * @property {number} total
 * @property {EngineUiManifest[]} manifests
 * @property {object} [provenance]
 */

export {}
