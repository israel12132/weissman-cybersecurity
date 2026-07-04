const ENGINE_ID: &str = "cloud_posture";

/// Live AWS API planes in the agentless CNAPP catalog (complete round).
pub const CNAPP_SERVICE_PLANES: &[&str] = &[
    "iam", "s3", "account", "ec2", "vpc", "elb", "eks", "ecs", "lambda", "rds", "elasticache",
    "kms", "secrets", "messaging", "ssm", "cloudtrail", "config", "guardduty", "accessanalyzer",
    "ecr", "acm", "dynamodb", "apigateway", "opensearch", "cloudfront", "route53", "eventbridge",
    "wafv2", "logs", "redshift", "documentdb", "neptune", "memorydb", "backup", "organizations",
    "sfn", "sso",
];
pub const CNAPP_PLANE_COUNT: usize = 37;

/// Default regions scanned for regional services when the caller does not pin a set.
pub const DEFAULT_SCAN_REGIONS: &[&str] = &[
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
];

const DANGEROUS_PORTS: &[i32] = &[
    22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5433, 5984, 6379, 8020, 9000,
    9042, 9200, 9300, 11211, 27017, 27018,
];

/// Severity ordering helper (higher = worse).
pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn sev_weight(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 22.0,
        "high" => 12.0,
        "medium" => 5.0,
        "low" => 1.5,
        _ => 0.0,
    }
}

/// Per-scan options, parsed from the job parameters forwarded by the run handler.
#[derive(Clone, Debug)]
pub struct CloudScanOptions {
    pub role_arn: String,
    pub external_id: String,
    pub session_name: String,
    pub regions: Vec<String>,
    pub services: BTreeSet<String>,
    pub min_severity: String,
    pub frameworks: Vec<String>,
    pub include_attack_paths: bool,
    pub include_security_graph: bool,
    pub max_resources_per_service: usize,
    pub access_key_max_age_days: u64,
    pub check_root_account: bool,
    pub check_password_policy: bool,
    pub check_imds: bool,
    pub check_flow_logs: bool,
    pub check_ssm_public_params: bool,
    pub check_cloudtrail: bool,
    pub check_rds: bool,
    pub check_lambda: bool,
    pub check_public_snapshots: bool,
    pub check_s3_policy_public: bool,
    pub check_iam_wildcards: bool,
    pub check_access_analyzer: bool,
    pub check_guardduty: bool,
    pub check_config_recorder: bool,
    pub check_eks: bool,
    pub check_elb: bool,
    pub check_secrets_manager: bool,
    pub check_messaging: bool,
    pub check_account_s3_block: bool,
    pub check_ecs: bool,
    pub check_elasticache: bool,
    pub check_lambda_urls: bool,
    pub check_ecr: bool,
    pub check_acm: bool,
    pub check_default_sg: bool,
    pub check_graph_paths: bool,
    pub check_s3_versioning: bool,
    pub check_dynamodb: bool,
    pub check_apigateway: bool,
    pub check_opensearch: bool,
    pub check_cloudfront: bool,
    pub check_route53: bool,
    pub check_eventbridge: bool,
    pub check_wafv2: bool,
    pub check_cloudwatch_logs: bool,
    pub check_redshift: bool,
    pub check_documentdb: bool,
    pub check_s3_object_lock: bool,
    pub check_neptune: bool,
    pub check_memorydb: bool,
    pub check_backup: bool,
    pub check_organizations: bool,
    pub check_sfn: bool,
    pub check_sso: bool,
    pub acm_expiry_days: u64,
    pub intensity: Intensity,
}

impl Default for CloudScanOptions {
    fn default() -> Self {
        Self {
            role_arn: String::new(),
            external_id: String::new(),
            session_name: String::new(),
            regions: Vec::new(),
            services: BTreeSet::new(),
            min_severity: "info".to_string(),
            frameworks: vec![
                "CIS".into(),
                "SOC2".into(),
                "ISO27001".into(),
                "PCI".into(),
                "NIST".into(),
                "GDPR".into(),
            ],
            include_attack_paths: true,
            include_security_graph: true,
            max_resources_per_service: 300,
            access_key_max_age_days: 90,
            check_root_account: true,
            check_password_policy: true,
            check_imds: true,
            check_flow_logs: true,
            check_ssm_public_params: true,
            check_cloudtrail: true,
            check_rds: true,
            check_lambda: true,
            check_public_snapshots: true,
            check_s3_policy_public: true,
            check_iam_wildcards: true,
            check_access_analyzer: true,
            check_guardduty: true,
            check_config_recorder: true,
            check_eks: true,
            check_elb: true,
            check_secrets_manager: true,
            check_messaging: true,
            check_account_s3_block: true,
            check_ecs: true,
            check_elasticache: true,
            check_lambda_urls: true,
            check_ecr: true,
            check_acm: true,
            check_default_sg: true,
            check_graph_paths: true,
            check_s3_versioning: true,
            check_dynamodb: true,
            check_apigateway: true,
            check_opensearch: true,
            check_cloudfront: true,
            check_route53: true,
            check_eventbridge: true,
            check_wafv2: true,
            check_cloudwatch_logs: true,
            check_redshift: true,
            check_documentdb: true,
            check_s3_object_lock: true,
            check_neptune: true,
            check_memorydb: true,
            check_backup: true,
            check_organizations: true,
            check_sfn: true,
            check_sso: true,
            acm_expiry_days: 30,
            intensity: Intensity::Normal,
        }
    }
}

impl CloudScanOptions {
    pub fn from_ctx(ctx: &EngineRunContext) -> Self {
        Self::from_arsenal(&ArsenalConfig::from_ctx(ctx))
    }

    pub fn from_arsenal(c: &ArsenalConfig) -> Self {
        let mut o = Self::default();
        o.role_arn = c
            .string("aws_cross_account_role_arn")
            .or_else(|| c.string("aws_role_arn"))
            .unwrap_or_default();
        o.external_id = c.string_or("aws_external_id", "");
        o.session_name = c.string_or("aws_role_session_name", "");
        o.regions = c.string_list("regions");
        if o.regions.is_empty() {
            o.regions = c.string_list("aws_regions");
        }
        let svc = c.string_list("services");
        if !svc.is_empty() {
            o.services = svc.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        }
        o.min_severity = c.string_or("min_severity", "info");
        let fw = c.string_list("frameworks");
        if !fw.is_empty() {
            o.frameworks = fw;
        }
        o.include_attack_paths = c.bool_or("include_attack_paths", true);
        o.include_security_graph = c.bool_or("include_security_graph", true);
        o.max_resources_per_service = c.usize_or("max_resources_per_service", 300).clamp(10, 5000);
        o.access_key_max_age_days = c.u64_or("access_key_max_age_days", 90).clamp(1, 3650);
        o.check_root_account = c.bool_or("check_root_account", true);
        o.check_password_policy = c.bool_or("check_password_policy", true);
        o.check_imds = c.bool_or("check_imds", true);
        o.check_flow_logs = c.bool_or("check_flow_logs", true);
        o.check_ssm_public_params = c.bool_or("check_ssm_public_params", true);
        o.check_cloudtrail = c.bool_or("check_cloudtrail", true);
        o.check_rds = c.bool_or("check_rds", true);
        o.check_lambda = c.bool_or("check_lambda", true);
        o.check_public_snapshots = c.bool_or("check_public_snapshots", true);
        o.check_s3_policy_public = c.bool_or("check_s3_policy_public", true);
        o.check_iam_wildcards = c.bool_or("check_iam_wildcards", true);
        o.check_access_analyzer = c.bool_or("check_access_analyzer", true);
        o.check_guardduty = c.bool_or("check_guardduty", true);
        o.check_config_recorder = c.bool_or("check_config_recorder", true);
        o.check_eks = c.bool_or("check_eks", true);
        o.check_elb = c.bool_or("check_elb", true);
        o.check_secrets_manager = c.bool_or("check_secrets_manager", true);
        o.check_messaging = c.bool_or("check_messaging", true);
        o.check_account_s3_block = c.bool_or("check_account_s3_block", true);
        o.check_ecs = c.bool_or("check_ecs", true);
        o.check_elasticache = c.bool_or("check_elasticache", true);
        o.check_lambda_urls = c.bool_or("check_lambda_urls", true);
        o.check_ecr = c.bool_or("check_ecr", true);
        o.check_acm = c.bool_or("check_acm", true);
        o.check_default_sg = c.bool_or("check_default_sg", true);
        o.check_graph_paths = c.bool_or("check_graph_paths", true);
        o.check_s3_versioning = c.bool_or("check_s3_versioning", true);
        o.check_dynamodb = c.bool_or("check_dynamodb", true);
        o.check_apigateway = c.bool_or("check_apigateway", true);
        o.check_opensearch = c.bool_or("check_opensearch", true);
        o.check_cloudfront = c.bool_or("check_cloudfront", true);
        o.check_route53 = c.bool_or("check_route53", true);
        o.check_eventbridge = c.bool_or("check_eventbridge", true);
        o.check_wafv2 = c.bool_or("check_wafv2", true);
        o.check_cloudwatch_logs = c.bool_or("check_cloudwatch_logs", true);
        o.check_redshift = c.bool_or("check_redshift", true);
        o.check_documentdb = c.bool_or("check_documentdb", true);
        o.check_s3_object_lock = c.bool_or("check_s3_object_lock", true);
        o.check_neptune = c.bool_or("check_neptune", true);
        o.check_memorydb = c.bool_or("check_memorydb", true);
        o.check_backup = c.bool_or("check_backup", true);
        o.check_organizations = c.bool_or("check_organizations", true);
        o.check_sfn = c.bool_or("check_sfn", true);
        o.check_sso = c.bool_or("check_sso", true);
        o.acm_expiry_days = c.u64_or("acm_expiry_days", 30).clamp(1, 365);
        o.intensity = c.intensity();
        o
    }

    fn wants(&self, service: &str) -> bool {
        self.services.is_empty() || self.services.contains(service)
    }

    fn effective_regions(&self) -> Vec<String> {
        if self.regions.is_empty() {
            DEFAULT_SCAN_REGIONS.iter().map(|s| s.to_string()).collect()
        } else {
            self.regions.clone()
        }
    }

    fn keep_severity(&self, sev: &str) -> bool {
        severity_rank(sev) >= severity_rank(&self.min_severity)
    }

    fn max_users(&self) -> usize {
        match self.intensity {
            Intensity::Light => 30,
            Intensity::Normal => 80,
            Intensity::Aggressive => 250,
        }
    }

    fn max_buckets(&self) -> usize {
        match self.intensity {
            Intensity::Light => 40,
            Intensity::Normal => 120,
            Intensity::Aggressive => self.max_resources_per_service,
        }
    }
}

