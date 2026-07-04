//! Agentless AWS Cloud Security Posture Management (CSPM / CNAPP) engine.
#![allow(clippy::pedantic, clippy::nursery, clippy::too_many_lines)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::cloud_integration_engine::{assume_role_sdk_config, CrossAccountAwsConfig};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::{print_result, EngineResult};
use aws_config::Region;
use aws_types::SdkConfig;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

include!("inc/types.inc.rs");
include!("inc/findings.inc.rs");
include!("inc/scanners.inc.rs");
include!("inc/analysis.inc.rs");
include!("inc/runner.inc.rs");
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_ordering() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("info") < severity_rank("low"));
    }

    #[test]
    fn options_default_frameworks() {
        let o = CloudScanOptions::default();
        assert!(o.frameworks.contains(&"CIS".to_string()));
        assert!(o.include_attack_paths);
    }

    #[test]
    fn letter_grade_boundaries() {
        assert_eq!(letter_grade(96.0), "A+");
        assert_eq!(letter_grade(50.0), "D");
    }

    #[test]
    fn cnapp_risk_register_ranks_by_severity() {
        let findings = vec![
            json!({
                "resource_id": "bucket-a",
                "resource_type": "s3_bucket",
                "domain": "data",
                "region": "us-east-1",
                "severity": "high",
            }),
            json!({
                "resource_id": "bucket-a",
                "resource_type": "s3_bucket",
                "domain": "data",
                "region": "us-east-1",
                "severity": "critical",
            }),
            json!({
                "category": "summary",
                "posture_score": 50,
            }),
        ];
        let reg = cnapp_risk_register(&findings);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0]["peak_severity"], "critical");
        assert!(reg[0]["risk_score"].as_i64().unwrap_or(0) >= 9);
    }

    #[test]
    fn cnapp_catalog_has_37_planes() {
        assert_eq!(CNAPP_PLANE_COUNT, 37);
        assert_eq!(CNAPP_SERVICE_PLANES.len(), CNAPP_PLANE_COUNT);
        let opts = CloudScanOptions::default();
        let catalog = cnapp_catalog_status(&opts);
        assert_eq!(catalog["catalog_status"], "complete");
        assert_eq!(catalog["plane_count"], 37);
        assert_eq!(catalog["planes"].as_array().unwrap().len(), 37);
    }
}
