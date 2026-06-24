//! Terraform analyzer: a tolerant, dependency-free HCL2 parser (blocks, labels, attributes,
//! nested blocks, lists, objects, heredocs, line + byte spans) plus a deep AWS / Azure / GCP policy
//! library. Findings are only emitted from values actually present in the configuration.

use super::model::{Finding, PolicyMeta, Severity};

// ──────────────────────────────────────────────────────────────────────────────
// HCL value + block model
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum HclValue {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
    List(Vec<HclValue>),
    Obj(Vec<(String, HclValue)>),
    /// Unquoted expression / reference / function call captured verbatim.
    Raw(String),
}

impl HclValue {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            HclValue::Str(s) | HclValue::Raw(s) => Some(s),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            HclValue::Bool(b) => Some(*b),
            HclValue::Str(s) | HclValue::Raw(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }
    #[must_use]
    pub fn as_num(&self) -> Option<f64> {
        match self {
            HclValue::Num(n) => Some(*n),
            HclValue::Str(s) | HclValue::Raw(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
    #[must_use]
    pub fn list_strings(&self) -> Vec<String> {
        match self {
            HclValue::List(v) => v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            HclValue::Str(s) | HclValue::Raw(s) => vec![s.clone()],
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct HclBlock {
    pub typ: String,
    pub labels: Vec<String>,
    pub line: usize,
    pub start: usize,
    pub end: usize,
    pub attrs: Vec<(String, HclValue, usize)>,
    pub blocks: Vec<HclBlock>,
}

impl HclBlock {
    #[must_use]
    pub fn attr(&self, key: &str) -> Option<&HclValue> {
        self.attrs.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| v)
    }
    #[must_use]
    pub fn attr_line(&self, key: &str) -> usize {
        self.attrs
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, _, l)| *l)
            .unwrap_or(self.line)
    }
    #[must_use]
    pub fn attr_str(&self, key: &str) -> Option<String> {
        self.attr(key).and_then(|v| v.as_str().map(str::to_string))
    }
    #[must_use]
    pub fn attr_bool(&self, key: &str) -> Option<bool> {
        self.attr(key).and_then(HclValue::as_bool)
    }
    #[must_use]
    pub fn attr_num(&self, key: &str) -> Option<f64> {
        self.attr(key).and_then(HclValue::as_num)
    }
    pub fn nested<'a>(&'a self, typ: &'a str) -> impl Iterator<Item = &'a HclBlock> + 'a {
        self.blocks.iter().filter(move |b| b.typ == typ)
    }
    #[must_use]
    pub fn resource_type(&self) -> &str {
        self.labels.first().map(String::as_str).unwrap_or("")
    }
    #[must_use]
    pub fn address(&self) -> String {
        if self.labels.is_empty() {
            self.typ.clone()
        } else {
            self.labels.join(".")
        }
    }
    #[must_use]
    pub fn raw<'a>(&self, content: &'a str) -> &'a str {
        content.get(self.start..self.end).unwrap_or("")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Parser
// ──────────────────────────────────────────────────────────────────────────────

struct P {
    ch: Vec<(usize, char)>,
    len: usize,
    i: usize,
    line: usize,
}

impl P {
    fn new(s: &str) -> Self {
        Self { ch: s.char_indices().collect(), len: s.len(), i: 0, line: 1 }
    }
    fn peek(&self) -> Option<char> {
        self.ch.get(self.i).map(|(_, c)| *c)
    }
    fn peek2(&self) -> Option<char> {
        self.ch.get(self.i + 1).map(|(_, c)| *c)
    }
    fn byte(&self) -> usize {
        self.ch.get(self.i).map(|(b, _)| *b).unwrap_or(self.len)
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        if c == '\n' {
            self.line += 1;
        }
        self.i += 1;
        Some(c)
    }
    fn skip_ws(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('#') => self.skip_line(),
                Some('/') if self.peek2() == Some('/') => self.skip_line(),
                Some('/') if self.peek2() == Some('*') => {
                    self.bump();
                    self.bump();
                    while let Some(c) = self.bump() {
                        if c == '*' && self.peek() == Some('/') {
                            self.bump();
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }
    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }
    fn parse_ident(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '*' {
                s.push(c);
                self.bump();
            } else {
                break;
            }
        }
        s
    }
    fn parse_string(&mut self) -> String {
        // assumes current char is '"'
        self.bump();
        let mut s = String::new();
        let mut interp_depth = 0usize;
        while let Some(c) = self.peek() {
            match c {
                '\\' if interp_depth == 0 => {
                    self.bump();
                    if let Some(n) = self.bump() {
                        match n {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            other => s.push(other),
                        }
                    }
                }
                '$' if self.peek2() == Some('{') => {
                    interp_depth += 1;
                    s.push('$');
                    self.bump();
                    s.push('{');
                    self.bump();
                }
                '{' if interp_depth > 0 => {
                    interp_depth += 1;
                    s.push('{');
                    self.bump();
                }
                '}' if interp_depth > 0 => {
                    interp_depth -= 1;
                    s.push('}');
                    self.bump();
                }
                '"' if interp_depth == 0 => {
                    self.bump();
                    break;
                }
                _ => {
                    s.push(c);
                    self.bump();
                }
            }
        }
        s
    }
    fn parse_heredoc(&mut self) -> String {
        // current at first '<'
        self.bump();
        self.bump(); // consume <<
        if self.peek() == Some('-') {
            self.bump();
        }
        let tag = self.parse_ident();
        // consume to end of line
        self.skip_line();
        if self.peek() == Some('\n') {
            self.bump();
        }
        let mut body = String::new();
        loop {
            // read one line
            let mut line = String::new();
            while let Some(c) = self.peek() {
                if c == '\n' {
                    self.bump();
                    break;
                }
                line.push(c);
                self.bump();
            }
            if line.trim() == tag {
                break;
            }
            if self.peek().is_none() && line.trim() != tag {
                body.push_str(&line);
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        body
    }
    fn parse_value(&mut self) -> HclValue {
        self.skip_ws();
        match self.peek() {
            Some('"') => HclValue::Str(self.parse_string()),
            Some('<') if self.peek2() == Some('<') => HclValue::Str(self.parse_heredoc()),
            Some('[') => self.parse_list(),
            Some('{') => self.parse_object(),
            Some(c) if c.is_ascii_digit() || (c == '-' && self.peek2().map(|d| d.is_ascii_digit()).unwrap_or(false)) => {
                self.parse_number_or_raw()
            }
            _ => self.parse_raw_expr(),
        }
    }
    fn parse_number_or_raw(&mut self) -> HclValue {
        let mut s = String::new();
        if self.peek() == Some('-') {
            s.push('-');
            self.bump();
        }
        let mut dot = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                s.push(c);
                self.bump();
            } else if c == '.' && !dot {
                dot = true;
                s.push(c);
                self.bump();
            } else {
                break;
            }
        }
        // if followed by expression chars, it's a raw expr
        if matches!(self.peek(), Some(c) if c.is_alphabetic() || c == '(') {
            let rest = self.parse_raw_token();
            return HclValue::Raw(format!("{}{}", s, rest));
        }
        s.parse::<f64>().map(HclValue::Num).unwrap_or(HclValue::Raw(s))
    }
    fn parse_raw_token(&mut self) -> String {
        let mut s = String::new();
        let mut depth_paren = 0i32;
        let mut depth_brack = 0i32;
        while let Some(c) = self.peek() {
            match c {
                '(' => depth_paren += 1,
                ')' => {
                    if depth_paren == 0 {
                        break;
                    }
                    depth_paren -= 1;
                }
                '[' => depth_brack += 1,
                ']' => {
                    if depth_brack == 0 {
                        break;
                    }
                    depth_brack -= 1;
                }
                ',' | '\n' if depth_paren == 0 && depth_brack == 0 => break,
                '}' if depth_paren == 0 && depth_brack == 0 => break,
                _ => {}
            }
            s.push(c);
            self.bump();
        }
        s.trim().to_string()
    }
    fn parse_raw_expr(&mut self) -> HclValue {
        // could be true/false/null or identifier/function call
        let start_i = self.i;
        let tok = self.parse_raw_token();
        let t = tok.trim();
        match t {
            "true" => HclValue::Bool(true),
            "false" => HclValue::Bool(false),
            "null" => HclValue::Null,
            "" => {
                // ensure progress
                if self.i == start_i {
                    self.bump();
                }
                HclValue::Raw(String::new())
            }
            _ => HclValue::Raw(t.to_string()),
        }
    }
    fn parse_list(&mut self) -> HclValue {
        self.bump(); // [
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(']') => {
                    self.bump();
                    break;
                }
                None => break,
                Some(',') => {
                    self.bump();
                }
                _ => {
                    let before = self.i;
                    items.push(self.parse_value());
                    if self.i == before {
                        self.bump();
                    }
                }
            }
        }
        HclValue::List(items)
    }
    fn parse_object(&mut self) -> HclValue {
        self.bump(); // {
        let mut pairs = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some('}') => {
                    self.bump();
                    break;
                }
                None => break,
                Some(',') => {
                    self.bump();
                }
                Some('"') => {
                    let key = self.parse_string();
                    self.skip_ws();
                    if matches!(self.peek(), Some('=') | Some(':')) {
                        self.bump();
                    }
                    let v = self.parse_value();
                    pairs.push((key, v));
                }
                _ => {
                    let before = self.i;
                    let key = self.parse_ident();
                    self.skip_ws();
                    if matches!(self.peek(), Some('=') | Some(':')) {
                        self.bump();
                        let v = self.parse_value();
                        pairs.push((key, v));
                    } else if self.i == before {
                        self.bump();
                    }
                }
            }
        }
        HclValue::Obj(pairs)
    }
    fn parse_body(&mut self, attrs: &mut Vec<(String, HclValue, usize)>, blocks: &mut Vec<HclBlock>) {
        loop {
            self.skip_ws();
            match self.peek() {
                Some('}') => {
                    self.bump();
                    break;
                }
                None => break,
                _ => {
                    let before = self.i;
                    let line = self.line;
                    let ident = self.parse_ident();
                    if ident.is_empty() {
                        self.bump();
                        continue;
                    }
                    self.skip_ws();
                    match self.peek() {
                        Some('=') if self.peek2() != Some('=') => {
                            self.bump();
                            let v = self.parse_value();
                            attrs.push((ident, v, line));
                        }
                        Some(':') => {
                            self.bump();
                            let v = self.parse_value();
                            attrs.push((ident, v, line));
                        }
                        _ => {
                            // nested block: collect labels then '{'
                            if let Some(b) = self.parse_block_tail(ident, line) {
                                blocks.push(b);
                            }
                        }
                    }
                    if self.i == before {
                        self.bump();
                    }
                }
            }
        }
    }
    fn parse_block_tail(&mut self, typ: String, line: usize) -> Option<HclBlock> {
        let start = self.byte();
        let mut labels = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some('"') => labels.push(self.parse_string()),
                Some('{') => {
                    self.bump();
                    let mut attrs = Vec::new();
                    let mut blocks = Vec::new();
                    self.parse_body(&mut attrs, &mut blocks);
                    let end = self.byte();
                    return Some(HclBlock { typ, labels, line, start, end, attrs, blocks });
                }
                Some(c) if c.is_alphanumeric() || c == '_' || c == '-' => {
                    labels.push(self.parse_ident());
                }
                _ => return None,
            }
        }
    }
    fn parse_top(&mut self) -> Vec<HclBlock> {
        let mut out = Vec::new();
        let mut guard = 0usize;
        loop {
            self.skip_ws();
            if self.peek().is_none() {
                break;
            }
            guard += 1;
            if guard > 1_000_000 {
                break;
            }
            let before = self.i;
            let line = self.line;
            let ident = self.parse_ident();
            if ident.is_empty() {
                self.bump();
                continue;
            }
            self.skip_ws();
            if matches!(self.peek(), Some('=')) {
                // top-level assignment (tfvars) — capture as a synthetic block attr
                self.bump();
                let _ = self.parse_value();
            } else if let Some(b) = self.parse_block_tail(ident, line) {
                out.push(b);
            }
            if self.i == before {
                self.bump();
            }
        }
        out
    }
}

#[must_use]
pub fn parse_hcl(content: &str) -> Vec<HclBlock> {
    P::new(content).parse_top()
}

// ──────────────────────────────────────────────────────────────────────────────
// Policy catalog (Terraform)
// ──────────────────────────────────────────────────────────────────────────────

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $prov:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "terraform",
            provider: $prov,
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

use Severity::{Critical, High, Medium};

pub const S3_PUBLIC_ACL: PolicyMeta = pol!("WZ-TF-AWS-S3-001", "S3 bucket grants public access via ACL", Critical, "aws", "An S3 bucket ACL allows public (anonymous) read or write access, exposing stored objects to the internet.", "Set the bucket ACL to 'private' and attach an aws_s3_bucket_public_access_block with all four flags true.", "T1530", "CWE-732", &["CIS-AWS-2.1.5", "https://aquasecurity.github.io/tfsec/checks/aws/s3/no-public-access-with-acl/"], &["CIS-AWS-2.1.5", "PCI-DSS-1.2.1", "NIST-AC-3", "SOC2-CC6.1", "ISO27001-A.9.1.2", "HIPAA-164.312(a)(1)"]);
pub const S3_PAB_DISABLED: PolicyMeta = pol!("WZ-TF-AWS-S3-002", "S3 public access block disables protection", High, "aws", "aws_s3_bucket_public_access_block has one or more protections disabled, allowing public ACLs/policies to take effect.", "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets all to true.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["CIS-AWS-2.1.5", "PCI-DSS-1.3", "NIST-AC-3", "SOC2-CC6.1"]);
pub const SG_OPEN_INGRESS: PolicyMeta = pol!("WZ-TF-AWS-SG-001", "Security group exposes ingress to 0.0.0.0/0", High, "aws", "A security group ingress rule allows traffic from any IPv4 address (0.0.0.0/0).", "Restrict cidr_blocks to known administrative ranges or front the service with a load balancer / bastion.", "T1190", "CWE-284", &["CIS-AWS-5.2", "https://aquasecurity.github.io/tfsec/checks/aws/ec2/no-public-ingress-sgr/"], &["CIS-AWS-5.2", "PCI-DSS-1.2.1", "NIST-SC-7", "SOC2-CC6.6", "ISO27001-A.13.1.1"]);
pub const SG_OPEN_ADMIN: PolicyMeta = pol!("WZ-TF-AWS-SG-002", "Admin port (SSH/RDP) open to the internet", Critical, "aws", "A security group exposes SSH (22) or RDP (3389) to 0.0.0.0/0, a top initial-access vector.", "Never expose 22/3389 publicly. Use SSM Session Manager, a bastion, or a VPN, and scope cidr_blocks tightly.", "T1190", "CWE-284", &["CIS-AWS-5.2", "CIS-AWS-5.3"], &["CIS-AWS-5.2", "CIS-AWS-5.3", "PCI-DSS-1.2.1", "NIST-SC-7", "MITRE-T1190"]);
pub const RDS_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-RDS-001", "RDS instance is publicly accessible", High, "aws", "aws_db_instance has publicly_accessible = true, placing the database on a public endpoint.", "Set publicly_accessible = false and reach the database from within the VPC only.", "T1190", "CWE-668", &["CIS-AWS-2.3"], &["CIS-AWS-2.3", "PCI-DSS-1.3.6", "NIST-SC-7", "HIPAA-164.312(e)(1)"]);
pub const RDS_UNENCRYPTED: PolicyMeta = pol!("WZ-TF-AWS-RDS-002", "RDS storage is not encrypted at rest", High, "aws", "aws_db_instance / aws_rds_cluster has storage_encrypted = false (or unset), leaving data at rest unencrypted.", "Set storage_encrypted = true and provide a kms_key_id.", "T1530", "CWE-311", &["CIS-AWS-2.3.1"], &["CIS-AWS-2.3.1", "PCI-DSS-3.4", "NIST-SC-28", "HIPAA-164.312(a)(2)(iv)", "SOC2-CC6.1"]);
pub const EBS_UNENCRYPTED: PolicyMeta = pol!("WZ-TF-AWS-EBS-001", "EBS volume is not encrypted", High, "aws", "aws_ebs_volume has encrypted = false (or unset), exposing block storage data at rest.", "Set encrypted = true and a kms_key_id, or enable account-wide aws_ebs_encryption_by_default.", "T1530", "CWE-311", &["CIS-AWS-2.2.1"], &["CIS-AWS-2.2.1", "PCI-DSS-3.4", "NIST-SC-28", "SOC2-CC6.1"]);
pub const IAM_WILDCARD: PolicyMeta = pol!("WZ-TF-AWS-IAM-001", "IAM policy grants wildcard action on all resources", Critical, "aws", "An IAM policy statement allows Action \"*\" on Resource \"*\" (full admin), enabling privilege escalation and lateral movement.", "Apply least privilege: scope Action and Resource to the minimum required ARNs and operations.", "T1098", "CWE-269", &["CIS-AWS-1.16", "https://aquasecurity.github.io/tfsec/checks/aws/iam/no-policy-wildcards/"], &["CIS-AWS-1.16", "NIST-AC-6", "SOC2-CC6.3", "ISO27001-A.9.2.3", "MITRE-T1098"]);
pub const IMDSV1: PolicyMeta = pol!("WZ-TF-AWS-EC2-001", "EC2 instance allows IMDSv1 (SSRF credential theft)", High, "aws", "aws_instance does not require IMDSv2 (metadata_options.http_tokens != \"required\"), enabling SSRF-based credential theft.", "Set metadata_options { http_tokens = \"required\", http_endpoint = \"enabled\" } to enforce IMDSv2.", "T1552.005", "CWE-918", &["https://aquasecurity.github.io/tfsec/checks/aws/ec2/enforce-http-token-imds/"], &["CIS-AWS-5.6", "NIST-SC-7", "MITRE-T1552.005"]);
pub const CLOUDTRAIL_DISABLED: PolicyMeta = pol!("WZ-TF-AWS-CT-001", "CloudTrail logging is disabled", High, "aws", "aws_cloudtrail has enable_logging = false, blinding audit and incident response.", "Set enable_logging = true and enable is_multi_region_trail with log file validation.", "T1562.008", "CWE-778", &["CIS-AWS-3.1"], &["CIS-AWS-3.1", "PCI-DSS-10.1", "NIST-AU-2", "SOC2-CC7.2", "MITRE-T1562.008"]);
pub const KMS_NO_ROTATION: PolicyMeta = pol!("WZ-TF-AWS-KMS-001", "KMS key rotation is not enabled", Medium, "aws", "aws_kms_key has enable_key_rotation = false (or unset), extending the blast radius of a compromised key.", "Set enable_key_rotation = true for customer-managed CMKs.", "T1552", "CWE-320", &["CIS-AWS-3.8"], &["CIS-AWS-3.8", "PCI-DSS-3.6.4", "NIST-SC-12"]);
pub const EBS_DEFAULT_ENC_OFF: PolicyMeta = pol!("WZ-TF-AWS-EBS-002", "Account-wide EBS default encryption is disabled", High, "aws", "aws_ebs_encryption_by_default has enabled = false, so new volumes are created unencrypted.", "Set enabled = true to encrypt all new EBS volumes by default.", "T1530", "CWE-311", &["CIS-AWS-2.2.1"], &["CIS-AWS-2.2.1", "NIST-SC-28", "PCI-DSS-3.4"]);
pub const REDSHIFT_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-RS-001", "Redshift cluster is publicly accessible", High, "aws", "aws_redshift_cluster has publicly_accessible = true.", "Set publicly_accessible = false; access the warehouse from inside the VPC.", "T1190", "CWE-668", &["https://aquasecurity.github.io/tfsec/checks/aws/redshift/"], &["NIST-SC-7", "PCI-DSS-1.3.6", "SOC2-CC6.6"]);
pub const ES_UNENCRYPTED: PolicyMeta = pol!("WZ-TF-AWS-ES-001", "OpenSearch/Elasticsearch not encrypted at rest", High, "aws", "encrypt_at_rest is disabled on an OpenSearch/Elasticsearch domain.", "Set encrypt_at_rest { enabled = true } and node_to_node_encryption { enabled = true }.", "T1530", "CWE-311", &["https://aquasecurity.github.io/tfsec/checks/aws/elastic-search/"], &["NIST-SC-28", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)"]);
pub const IAM_PW_WEAK: PolicyMeta = pol!("WZ-TF-AWS-IAM-002", "IAM password policy is weak", Medium, "aws", "aws_iam_account_password_policy enforces a minimum length below 14 characters.", "Set minimum_password_length >= 14 and require symbols, numbers and mixed case with expiry/reuse limits.", "T1110", "CWE-521", &["CIS-AWS-1.8"], &["CIS-AWS-1.8", "PCI-DSS-8.2.3", "NIST-IA-5"]);
pub const EFS_UNENCRYPTED: PolicyMeta = pol!("WZ-TF-AWS-EFS-001", "EFS file system not encrypted at rest", High, "aws", "aws_efs_file_system has encrypted = false (or unset).", "Set encrypted = true and supply a kms_key_id.", "T1530", "CWE-311", &["https://aquasecurity.github.io/tfsec/checks/aws/efs/enable-at-rest-encryption/"], &["NIST-SC-28", "PCI-DSS-3.4", "HIPAA-164.312(a)(2)(iv)"]);
pub const AZ_STORAGE_HTTP: PolicyMeta = pol!("WZ-TF-AZ-ST-001", "Azure Storage allows unencrypted HTTP traffic", High, "azure", "azurerm_storage_account has enable_https_traffic_only = false, permitting cleartext access.", "Set enable_https_traffic_only = true (or https_traffic_only_enabled = true).", "T1040", "CWE-319", &["CIS-Azure-3.1"], &["CIS-Azure-3.1", "PCI-DSS-4.1", "NIST-SC-8"]);
pub const AZ_STORAGE_PUBLIC: PolicyMeta = pol!("WZ-TF-AZ-ST-002", "Azure Storage allows public blob access", High, "azure", "azurerm_storage_account allows public blob access (allow_nested_items_to_be_public / allow_blob_public_access = true).", "Set the public-access flag to false and use SAS tokens or private endpoints.", "T1530", "CWE-732", &["CIS-Azure-3.7"], &["CIS-Azure-3.7", "PCI-DSS-1.2", "NIST-AC-3"]);
pub const AZ_STORAGE_TLS: PolicyMeta = pol!("WZ-TF-AZ-ST-003", "Azure Storage min TLS below 1.2", Medium, "azure", "azurerm_storage_account min_tls_version is below TLS1_2.", "Set min_tls_version = \"TLS1_2\".", "T1040", "CWE-326", &["CIS-Azure-3.12"], &["CIS-Azure-3.12", "PCI-DSS-4.1", "NIST-SC-8"]);
pub const AZ_NSG_OPEN: PolicyMeta = pol!("WZ-TF-AZ-NSG-001", "Azure NSG allows inbound from any source", High, "azure", "An azurerm_network_security_rule allows inbound traffic from '*' or 'Internet' / 0.0.0.0/0.", "Restrict source_address_prefix to specific ranges; never expose management ports to the internet.", "T1190", "CWE-284", &["CIS-Azure-6.1", "CIS-Azure-6.2"], &["CIS-Azure-6.1", "CIS-Azure-6.2", "NIST-SC-7", "PCI-DSS-1.2.1"]);
pub const AZ_PG_SSL: PolicyMeta = pol!("WZ-TF-AZ-DB-001", "Azure database SSL enforcement disabled", High, "azure", "azurerm_postgresql_server / mysql_server has ssl_enforcement_enabled = false.", "Set ssl_enforcement_enabled = true and ssl_minimal_tls_version_enforced = \"TLS1_2\".", "T1040", "CWE-319", &["CIS-Azure-4.x"], &["NIST-SC-8", "PCI-DSS-4.1", "HIPAA-164.312(e)(1)"]);
pub const AZ_AKS_RBAC: PolicyMeta = pol!("WZ-TF-AZ-AKS-001", "AKS cluster has RBAC disabled", High, "azure", "azurerm_kubernetes_cluster has role_based_access_control disabled.", "Enable Azure RBAC / Kubernetes RBAC and integrate with Entra ID.", "T1078", "CWE-284", &["CIS-Azure-8.x"], &["NIST-AC-3", "SOC2-CC6.3"]);
pub const GCP_BUCKET_PUBLIC: PolicyMeta = pol!("WZ-TF-GCP-GCS-001", "GCS bucket granted to allUsers/allAuthenticatedUsers", Critical, "gcp", "A google_storage_bucket_iam_member/binding grants a role to allUsers or allAuthenticatedUsers, exposing objects publicly.", "Remove allUsers/allAuthenticatedUsers members and use scoped principals; enable uniform bucket-level access + public access prevention.", "T1530", "CWE-732", &["CIS-GCP-5.1"], &["CIS-GCP-5.1", "PCI-DSS-1.2", "NIST-AC-3", "ISO27001-A.9.1.2"]);
pub const GCP_FW_OPEN: PolicyMeta = pol!("WZ-TF-GCP-FW-001", "GCP firewall allows ingress from 0.0.0.0/0", High, "gcp", "A google_compute_firewall allows ingress from 0.0.0.0/0.", "Scope source_ranges to known networks; never expose SSH(22)/RDP(3389) to the internet.", "T1190", "CWE-284", &["CIS-GCP-3.6", "CIS-GCP-3.7"], &["CIS-GCP-3.6", "CIS-GCP-3.7", "NIST-SC-7", "PCI-DSS-1.2.1"]);
pub const GCP_SQL_PUBLIC: PolicyMeta = pol!("WZ-TF-GCP-SQL-001", "Cloud SQL exposed to all networks / no SSL", High, "gcp", "google_sql_database_instance authorizes 0.0.0.0/0 or does not require SSL.", "Remove the 0.0.0.0/0 authorized network, set require_ssl = true and prefer private IP.", "T1190", "CWE-668", &["CIS-GCP-6.x"], &["NIST-SC-7", "PCI-DSS-1.3.6", "HIPAA-164.312(e)(1)"]);
pub const GCP_ABAC: PolicyMeta = pol!("WZ-TF-GCP-GKE-001", "GKE legacy ABAC is enabled", High, "gcp", "google_container_cluster enables legacy_abac, bypassing RBAC controls.", "Disable legacy ABAC (enabled = false) and rely on Kubernetes RBAC.", "T1078", "CWE-284", &["CIS-GCP-7.x"], &["NIST-AC-3", "SOC2-CC6.3"]);
pub const PROVIDER_HARDCODED_CREDS: PolicyMeta = pol!("WZ-TF-GEN-001", "Hard-coded cloud credentials in provider block", Critical, "generic", "A provider block embeds static access_key/secret_key/credentials in source, leaking them via VCS.", "Remove static credentials; use environment variables, OIDC, instance roles or a secrets manager.", "T1552.001", "CWE-798", &["https://aquasecurity.github.io/tfsec/checks/general/secrets/"], &["CIS-AWS-1.x", "NIST-IA-5", "PCI-DSS-8.2.1", "MITRE-T1552.001"]);
pub const MODULE_UNPINNED: PolicyMeta = pol!("WZ-TF-SUPPLY-001", "Terraform module source is not pinned to an immutable version", High, "generic", "A module block fetches from a mutable git ref or registry without a version pin, enabling supply-chain implant via a compromised upstream.", "Pin git sources with ?ref=<tag|sha> and registry modules with version = \"x.y.z\".", "T1195.001", "CWE-494", &["CIS-AWS-1.x"], &["NIST-SA-12", "SOC2-CC8.1", "MITRE-T1195.001"]);
pub const S3_POLICY_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-S3-003", "S3 bucket policy grants public Principal", Critical, "aws", "aws_s3_bucket_policy allows Principal \"*\" or AWS \"*\" to access objects.", "Remove public principals; use OAI/OAC for CloudFront or scoped IAM roles.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["CIS-AWS-2.1.5", "PCI-DSS-1.2.1", "NIST-AC-3"]);
pub const LAMBDA_URL_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-LMB-001", "Lambda function URL allows unauthenticated invoke", Critical, "aws", "aws_lambda_function_url has authorization_type NONE, exposing the function to the internet.", "Set authorization_type = AWS_IAM or use API Gateway with authorizer.", "T1190", "CWE-306", &["CIS-AWS-Lambda"], &["NIST-AC-3", "SOC2-CC6.1", "MITRE-T1190"]);
pub const ECS_PRIVILEGED: PolicyMeta = pol!("WZ-TF-AWS-ECS-001", "ECS task container runs privileged", Critical, "aws", "aws_ecs_task_definition sets privileged = true on a container definition.", "Set privileged = false; use specific Linux capabilities if needed.", "T1610", "CWE-250", &["CIS-AWS-ECS"], &["NIST-AC-6", "MITRE-T1610"]);
pub const TF_BACKEND_PLAIN: PolicyMeta = pol!("WZ-TF-GEN-002", "Terraform S3 backend without encryption", High, "generic", "terraform backend \"s3\" has encrypt = false or omits encryption, storing state in cleartext.", "Set encrypt = true and enable bucket default encryption + versioning.", "T1552", "CWE-311", &["CIS-AWS-2.1.x"], &["NIST-SC-28", "PCI-DSS-3.4", "SOC2-CC6.1"]);
pub const PROVIDER_UNPINNED: PolicyMeta = pol!("WZ-TF-SUPPLY-002", "Terraform required_providers entry has no version constraint", Medium, "generic", "required_providers omits version, allowing provider upgrades that can change resource behaviour.", "Pin every provider: version = \"~> x.y\".", "T1195.001", "CWE-1104", &["CIS-AWS-1.x"], &["NIST-SA-12", "SOC2-CC8.1"]);
pub const ECR_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-ECR-001", "ECR repository policy allows public pull", High, "aws", "aws_ecr_repository_policy grants Principal * read access to images.", "Restrict ecr:BatchGetImage to trusted IAM roles; enable image scanning.", "T1190", "CWE-732", &["CIS-AWS-ECR"], &["NIST-AC-3", "SOC2-CC6.1"]);
pub const APIGW_NO_AUTH: PolicyMeta = pol!("WZ-TF-AWS-APIGW-001", "API Gateway method without authorization", High, "aws", "aws_api_gateway_method has authorization = NONE on a non-OPTIONS route.", "Use AWS_IAM, Cognito, or Lambda authorizer.", "T1190", "CWE-306", &["OWASP-API2"], &["NIST-AC-3", "PCI-DSS-6.5.10"]);
pub const SNS_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-SNS-001", "SNS topic policy allows public publish/subscribe", High, "aws", "aws_sns_topic_policy grants Principal * access.", "Scope SNS topic policy to specific AWS principals.", "T1190", "CWE-732", &["CIS-AWS-SNS"], &["NIST-AC-3", "SOC2-CC6.1"]);
pub const KMS_POLICY_PUBLIC: PolicyMeta = pol!("WZ-TF-AWS-KMS-002", "KMS key policy grants public Principal", Critical, "aws", "aws_kms_key_policy allows Principal * administrative or decrypt actions.", "Restrict key policy to specific account roles and services.", "T1098", "CWE-732", &["CIS-AWS-3.8"], &["NIST-AC-6", "PCI-DSS-3.4"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        S3_PUBLIC_ACL, S3_PAB_DISABLED, S3_POLICY_PUBLIC, SG_OPEN_INGRESS, SG_OPEN_ADMIN, RDS_PUBLIC, RDS_UNENCRYPTED,
        EBS_UNENCRYPTED, IAM_WILDCARD, IMDSV1, CLOUDTRAIL_DISABLED, KMS_NO_ROTATION, KMS_POLICY_PUBLIC, EBS_DEFAULT_ENC_OFF,
        REDSHIFT_PUBLIC, ES_UNENCRYPTED, IAM_PW_WEAK, EFS_UNENCRYPTED, LAMBDA_URL_PUBLIC, ECS_PRIVILEGED, ECR_PUBLIC, APIGW_NO_AUTH, SNS_PUBLIC,
        AZ_STORAGE_HTTP, AZ_STORAGE_PUBLIC,
        AZ_STORAGE_TLS, AZ_NSG_OPEN, AZ_PG_SSL, AZ_AKS_RBAC, GCP_BUCKET_PUBLIC, GCP_FW_OPEN, GCP_SQL_PUBLIC,
        GCP_ABAC, PROVIDER_HARDCODED_CREDS, MODULE_UNPINNED, TF_BACKEND_PLAIN, PROVIDER_UNPINNED,
    ]
}

// ──────────────────────────────────────────────────────────────────────────────
// Evaluation
// ──────────────────────────────────────────────────────────────────────────────

fn is_open_cidr(c: &str) -> bool {
    let c = c.trim();
    c == "0.0.0.0/0" || c == "::/0" || c == "*" || c.eq_ignore_ascii_case("internet") || c.eq_ignore_ascii_case("any")
}

fn ports_include_admin(from: Option<f64>, to: Option<f64>) -> bool {
    match (from, to) {
        (Some(f), Some(t)) => {
            let (lo, hi) = (f.min(t), f.max(t));
            (lo..=hi).contains(&22.0) || (lo..=hi).contains(&3389.0) || (lo == 0.0 && hi == 0.0)
        }
        _ => false,
    }
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let blocks = parse_hcl(content);
    let mut out = Vec::new();
    for b in &blocks {
        match b.typ.as_str() {
            "provider" => check_provider(file, b, &mut out),
            "resource" => check_resource(file, content, b, &mut out),
            "module" => check_module(file, b, &mut out),
            "terraform" => check_terraform_block(file, content, b, &mut out),
            _ => {}
        }
    }
    out
}

fn check_terraform_block(file: &str, content: &str, b: &HclBlock, out: &mut Vec<Finding>) {
    let raw = b.raw(content);
    for backend in b.nested("backend") {
        if backend.labels.first().map(|s| s.as_str()) == Some("s3") {
            if backend.attr_bool("encrypt") == Some(false) {
                out.push(
                    Finding::new(TF_BACKEND_PLAIN, "terraform.backend.s3", file)
                        .at(backend.line)
                        .observed("encrypt = false")
                        .fix("encrypt = true"),
                );
            } else if backend.attr("encrypt").is_none() {
                out.push(
                    Finding::new(TF_BACKEND_PLAIN, "terraform.backend.s3", file)
                        .at(backend.line)
                        .observed("encrypt not set on S3 backend")
                        .fix("encrypt = true"),
                );
            }
        }
    }
    if raw.contains("required_providers") {
        for line in raw.lines() {
            let l = line.trim();
            if l.contains('=') && !l.contains("version") && !l.starts_with('#') && l.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
                let name = l.split('=').next().unwrap_or("").trim();
                if !name.is_empty() && name != "required_providers" && name != "source" {
                    out.push(
                        Finding::new(PROVIDER_UNPINNED, format!("required_providers.{name}"), file)
                            .at(b.line)
                            .observed(format!("provider '{name}' block without version in terraform {{}}")),
                    );
                    break;
                }
            }
        }
    }
}

fn check_module(file: &str, b: &HclBlock, out: &mut Vec<Finding>) {
    let addr = b.address();
    let source = b.attr_str("source").unwrap_or_default();
    if source.is_empty() || source.starts_with("./") || source.starts_with("../") {
        return;
    }
    let ver_raw = b.attr_str("version");
    let version = ver_raw.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let is_git = source.contains("git::")
        || (source.contains("github.com") && !source.contains("registry.terraform.io"))
        || source.contains("gitlab.com");
    let has_ref = source.contains("?ref=") || source.contains("&ref=");
    if is_git && !has_ref {
        out.push(
            Finding::new(MODULE_UNPINNED, &addr, file)
                .at(b.attr_line("source"))
                .observed(format!("source = \"{source}\" (no ?ref= pin)"))
                .fix("source = \"git::https://github.com/org/repo.git?ref=v1.2.3\""),
        );
        return;
    }
    if version.is_none() && !is_git {
        out.push(
            Finding::new(MODULE_UNPINNED, &addr, file)
                .at(b.attr_line("source"))
                .observed(format!("source = \"{source}\" without version ="))
                .fix(format!("version = \"x.y.z\"  # pin the {addr} module")),
        );
    }
}

fn check_provider(file: &str, b: &HclBlock, out: &mut Vec<Finding>) {
    for key in ["access_key", "secret_key", "client_secret", "password", "token"] {
        if let Some(HclValue::Str(s)) = b.attr(key) {
            // only literal secrets (not var. / interpolations) count
            if !s.contains("${") && !s.starts_with("var.") && s.len() >= 8 && !s.is_empty() {
                out.push(
                    Finding::new(PROVIDER_HARDCODED_CREDS, format!("provider.{}", b.labels.first().cloned().unwrap_or_default()), file)
                        .at(b.attr_line(key))
                        .observed(format!("{} = \"{}\"", key, mask(s)))
                        .fix(format!("# remove the literal value; read from env/secret manager\n{} = var.{}", key, key)),
                );
            }
        }
    }
}

fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 4 {
        return "****".to_string();
    }
    let head: String = s.chars().take(2).collect();
    let tail: String = s.chars().rev().take(2).collect::<String>().chars().rev().collect();
    format!("{}…{}", head, tail)
}

#[allow(clippy::too_many_lines)]
fn check_resource(file: &str, content: &str, b: &HclBlock, out: &mut Vec<Finding>) {
    let rtype = b.resource_type().to_string();
    let addr = b.address();
    let line = b.line;
    match rtype.as_str() {
        "aws_s3_bucket" => {
            if let Some(acl) = b.attr_str("acl") {
                if acl == "public-read" || acl == "public-read-write" {
                    out.push(
                        Finding::new(S3_PUBLIC_ACL, &addr, file)
                            .at(b.attr_line("acl"))
                            .observed(format!("acl = \"{}\"", acl))
                            .fix("acl = \"private\""),
                    );
                }
            }
        }
        "aws_s3_bucket_public_access_block" => {
            for flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"] {
                if b.attr_bool(flag) == Some(false) {
                    out.push(
                        Finding::new(S3_PAB_DISABLED, &addr, file)
                            .at(b.attr_line(flag))
                            .observed(format!("{} = false", flag))
                            .fix(format!("{} = true", flag)),
                    );
                }
            }
        }
        "aws_security_group" => {
            for ing in b.nested("ingress") {
                let cidrs = ing.attr("cidr_blocks").map(HclValue::list_strings).unwrap_or_default();
                let v6 = ing.attr("ipv6_cidr_blocks").map(HclValue::list_strings).unwrap_or_default();
                if cidrs.iter().chain(v6.iter()).any(|c| is_open_cidr(c)) {
                    let admin = ports_include_admin(ing.attr_num("from_port"), ing.attr_num("to_port"));
                    let pol = if admin { SG_OPEN_ADMIN } else { SG_OPEN_INGRESS };
                    out.push(
                        Finding::new(pol, &addr, file)
                            .at(ing.line)
                            .observed(format!("ingress cidr_blocks include 0.0.0.0/0 (from_port={:?})", ing.attr_num("from_port")))
                            .fix("cidr_blocks = [\"10.0.0.0/8\"] # restrict to known ranges"),
                    );
                }
            }
        }
        "aws_security_group_rule" => {
            if b.attr_str("type").as_deref() == Some("ingress") {
                let cidrs = b.attr("cidr_blocks").map(HclValue::list_strings).unwrap_or_default();
                if cidrs.iter().any(|c| is_open_cidr(c)) {
                    let admin = ports_include_admin(b.attr_num("from_port"), b.attr_num("to_port"));
                    let pol = if admin { SG_OPEN_ADMIN } else { SG_OPEN_INGRESS };
                    out.push(Finding::new(pol, &addr, file).at(line).observed("ingress cidr_blocks include 0.0.0.0/0"));
                }
            }
        }
        "aws_db_instance" | "aws_rds_cluster" => {
            if b.attr_bool("publicly_accessible") == Some(true) {
                out.push(Finding::new(RDS_PUBLIC, &addr, file).at(b.attr_line("publicly_accessible")).observed("publicly_accessible = true").fix("publicly_accessible = false"));
            }
            if matches!(b.attr_bool("storage_encrypted"), Some(false) | None) {
                out.push(Finding::new(RDS_UNENCRYPTED, &addr, file).at(line).observed("storage_encrypted not set to true").fix("storage_encrypted = true"));
            }
        }
        "aws_ebs_volume" => {
            if matches!(b.attr_bool("encrypted"), Some(false) | None) {
                out.push(Finding::new(EBS_UNENCRYPTED, &addr, file).at(line).observed("encrypted not set to true").fix("encrypted = true"));
            }
        }
        "aws_ebs_encryption_by_default" => {
            if b.attr_bool("enabled") == Some(false) {
                out.push(Finding::new(EBS_DEFAULT_ENC_OFF, &addr, file).at(b.attr_line("enabled")).observed("enabled = false").fix("enabled = true"));
            }
        }
        "aws_s3_bucket_policy" => {
            let pol_raw = b.raw(content);
            if pol_raw.contains("\"Principal\"") && (pol_raw.contains("\"*\"") || pol_raw.contains("AWS\":\"*\"")) {
                out.push(Finding::new(S3_POLICY_PUBLIC, &addr, file).at(line).observed("Principal * in bucket policy"));
            }
        }
        "aws_lambda_function_url" => {
            if b.attr_str("authorization_type").map(|s| s.eq_ignore_ascii_case("NONE")).unwrap_or(true) {
                out.push(Finding::new(LAMBDA_URL_PUBLIC, &addr, file).at(line).observed("authorization_type NONE or unset").fix("authorization_type = \"AWS_IAM\""));
            }
        }
        "aws_ecs_task_definition" => {
            let raw = b.raw(content);
            if raw.contains("privileged") && (raw.contains("true") || raw.contains("\"true\"")) {
                out.push(Finding::new(ECS_PRIVILEGED, &addr, file).at(line).observed("container_definitions privileged = true"));
            }
        }
        "aws_ecr_repository_policy" | "aws_kms_key_policy" | "aws_sns_topic_policy" => {
            let pol_raw = b.raw(content);
            if pol_raw.contains("\"Principal\"") && (pol_raw.contains("\"*\"") || pol_raw.contains("AWS\":\"*\"")) {
                let pol = match rtype.as_str() {
                    "aws_ecr_repository_policy" => ECR_PUBLIC,
                    "aws_kms_key_policy" => KMS_POLICY_PUBLIC,
                    _ => SNS_PUBLIC,
                };
                out.push(Finding::new(pol, &addr, file).at(line).observed("Principal * in policy"));
            }
        }
        "aws_api_gateway_method" => {
            let auth = b.attr_str("authorization").unwrap_or_default();
            let http = b.attr_str("http_method").unwrap_or_default();
            if auth.eq_ignore_ascii_case("NONE") && !http.eq_ignore_ascii_case("OPTIONS") {
                out.push(Finding::new(APIGW_NO_AUTH, &addr, file).at(line).observed("authorization = NONE").fix("authorization = \"AWS_IAM\""));
            }
        }
        "aws_iam_policy" | "aws_iam_role_policy" | "aws_iam_group_policy" | "aws_iam_user_policy" => {
            let raw = b.raw(content);
            if has_iam_wildcard(raw) {
                out.push(Finding::new(IAM_WILDCARD, &addr, file).at(line).observed("Effect Allow with Action \"*\" and Resource \"*\""));
            }
        }
        "aws_instance" => {
            let enforced = b
                .nested("metadata_options")
                .next()
                .and_then(|m| m.attr_str("http_tokens"))
                .map(|t| t == "required")
                .unwrap_or(false);
            if !enforced {
                out.push(Finding::new(IMDSV1, &addr, file).at(line).observed("metadata_options.http_tokens != \"required\"").fix("metadata_options {\n  http_tokens = \"required\"\n  http_endpoint = \"enabled\"\n}"));
            }
        }
        "aws_cloudtrail" => {
            if b.attr_bool("enable_logging") == Some(false) {
                out.push(Finding::new(CLOUDTRAIL_DISABLED, &addr, file).at(b.attr_line("enable_logging")).observed("enable_logging = false").fix("enable_logging = true"));
            }
        }
        "aws_kms_key" => {
            if matches!(b.attr_bool("enable_key_rotation"), Some(false) | None) {
                out.push(Finding::new(KMS_NO_ROTATION, &addr, file).at(line).observed("enable_key_rotation not set to true").fix("enable_key_rotation = true"));
            }
        }
        "aws_redshift_cluster" => {
            if b.attr_bool("publicly_accessible") == Some(true) {
                out.push(Finding::new(REDSHIFT_PUBLIC, &addr, file).at(line).observed("publicly_accessible = true").fix("publicly_accessible = false"));
            }
        }
        "aws_elasticsearch_domain" | "aws_opensearch_domain" => {
            let enc = b.nested("encrypt_at_rest").next().and_then(|e| e.attr_bool("enabled")).unwrap_or(false);
            if !enc {
                out.push(Finding::new(ES_UNENCRYPTED, &addr, file).at(line).observed("encrypt_at_rest.enabled != true").fix("encrypt_at_rest { enabled = true }"));
            }
        }
        "aws_iam_account_password_policy" => {
            if b.attr_num("minimum_password_length").map(|n| n < 14.0).unwrap_or(true) {
                out.push(Finding::new(IAM_PW_WEAK, &addr, file).at(line).observed(format!("minimum_password_length = {:?}", b.attr_num("minimum_password_length"))).fix("minimum_password_length = 14"));
            }
        }
        "aws_efs_file_system" => {
            if matches!(b.attr_bool("encrypted"), Some(false) | None) {
                out.push(Finding::new(EFS_UNENCRYPTED, &addr, file).at(line).observed("encrypted not set to true").fix("encrypted = true"));
            }
        }
        "azurerm_storage_account" => {
            if b.attr_bool("enable_https_traffic_only") == Some(false) || b.attr_bool("https_traffic_only_enabled") == Some(false) {
                out.push(Finding::new(AZ_STORAGE_HTTP, &addr, file).at(line).observed("enable_https_traffic_only = false").fix("enable_https_traffic_only = true"));
            }
            if b.attr_bool("allow_nested_items_to_be_public") == Some(true) || b.attr_bool("allow_blob_public_access") == Some(true) {
                out.push(Finding::new(AZ_STORAGE_PUBLIC, &addr, file).at(line).observed("public blob access allowed").fix("allow_nested_items_to_be_public = false"));
            }
            if let Some(tls) = b.attr_str("min_tls_version") {
                if tls != "TLS1_2" && tls != "TLS1_3" {
                    out.push(Finding::new(AZ_STORAGE_TLS, &addr, file).at(b.attr_line("min_tls_version")).observed(format!("min_tls_version = \"{}\"", tls)).fix("min_tls_version = \"TLS1_2\""));
                }
            }
        }
        "azurerm_network_security_rule" => {
            let dir = b.attr_str("direction").unwrap_or_default();
            let access = b.attr_str("access").unwrap_or_default();
            let src = b.attr_str("source_address_prefix").unwrap_or_default();
            let srcs = b.attr("source_address_prefixes").map(HclValue::list_strings).unwrap_or_default();
            let open = is_open_cidr(&src) || srcs.iter().any(|c| is_open_cidr(c));
            if dir.eq_ignore_ascii_case("Inbound") && access.eq_ignore_ascii_case("Allow") && open {
                out.push(Finding::new(AZ_NSG_OPEN, &addr, file).at(line).observed(format!("source_address_prefix = \"{}\"", src)).fix("source_address_prefix = \"10.0.0.0/8\""));
            }
        }
        "azurerm_postgresql_server" | "azurerm_mysql_server" => {
            if b.attr_bool("ssl_enforcement_enabled") == Some(false) {
                out.push(Finding::new(AZ_PG_SSL, &addr, file).at(line).observed("ssl_enforcement_enabled = false").fix("ssl_enforcement_enabled = true"));
            }
        }
        "azurerm_kubernetes_cluster" => {
            let rbac_off = b
                .nested("role_based_access_control")
                .next()
                .and_then(|r| r.attr_bool("enabled"))
                .map(|e| !e)
                .unwrap_or(false);
            if rbac_off {
                out.push(Finding::new(AZ_AKS_RBAC, &addr, file).at(line).observed("role_based_access_control.enabled = false").fix("role_based_access_control { enabled = true }"));
            }
        }
        "google_storage_bucket_iam_member" | "google_storage_bucket_iam_binding" => {
            let mut members = b.attr("members").map(HclValue::list_strings).unwrap_or_default();
            if let Some(m) = b.attr_str("member") {
                members.push(m);
            }
            if members.iter().any(|m| m == "allUsers" || m == "allAuthenticatedUsers") {
                out.push(Finding::new(GCP_BUCKET_PUBLIC, &addr, file).at(line).observed("member allUsers/allAuthenticatedUsers").fix("# remove allUsers/allAuthenticatedUsers"));
            }
        }
        "google_compute_firewall" => {
            let ranges = b.attr("source_ranges").map(HclValue::list_strings).unwrap_or_default();
            if ranges.iter().any(|c| is_open_cidr(c)) {
                out.push(Finding::new(GCP_FW_OPEN, &addr, file).at(line).observed("source_ranges include 0.0.0.0/0").fix("source_ranges = [\"10.0.0.0/8\"]"));
            }
        }
        "google_sql_database_instance" => {
            let raw = b.raw(content);
            if raw.contains("0.0.0.0/0") || raw.contains("require_ssl = false") || raw.contains("require_ssl=false") {
                out.push(Finding::new(GCP_SQL_PUBLIC, &addr, file).at(line).observed("authorized 0.0.0.0/0 or require_ssl=false"));
            }
        }
        "google_container_cluster" => {
            let abac = b.nested("legacy_abac").next().and_then(|l| l.attr_bool("enabled")).unwrap_or(false);
            if abac {
                out.push(Finding::new(GCP_ABAC, &addr, file).at(line).observed("legacy_abac.enabled = true").fix("legacy_abac { enabled = false }"));
            }
        }
        _ => {}
    }
}

fn has_iam_wildcard(raw: &str) -> bool {
    let norm: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let action_star = norm.contains("\"Action\":\"*\"") || norm.contains("\"Action\":[\"*\"]");
    let resource_star = norm.contains("\"Resource\":\"*\"") || norm.contains("\"Resource\":[\"*\"]");
    let allow = norm.contains("\"Effect\":\"Allow\"");
    action_star && resource_star && allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resource_with_nested_block() {
        let tf = r#"
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let blocks = parse_hcl(tf);
        assert_eq!(blocks.len(), 1);
        let b = &blocks[0];
        assert_eq!(b.typ, "resource");
        assert_eq!(b.labels, vec!["aws_security_group", "web"]);
        assert_eq!(b.nested("ingress").count(), 1);
    }

    #[test]
    fn flags_open_admin_port() {
        let tf = r#"
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let f = evaluate("sg.tf", tf);
        assert!(f.iter().any(|x| x.policy.id == SG_OPEN_ADMIN.id), "expected open admin finding");
    }

    #[test]
    fn flags_public_s3_and_rds() {
        let tf = r#"
resource "aws_s3_bucket" "b" { acl = "public-read" }
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted = false
}
"#;
        let f = evaluate("main.tf", tf);
        assert!(f.iter().any(|x| x.policy.id == S3_PUBLIC_ACL.id));
        assert!(f.iter().any(|x| x.policy.id == RDS_PUBLIC.id));
        assert!(f.iter().any(|x| x.policy.id == RDS_UNENCRYPTED.id));
    }

    #[test]
    fn flags_iam_wildcard_heredoc() {
        let tf = r#"
resource "aws_iam_policy" "admin" {
  policy = <<EOF
{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "*", "Resource": "*" } ] }
EOF
}
"#;
        let f = evaluate("iam.tf", tf);
        assert!(f.iter().any(|x| x.policy.id == IAM_WILDCARD.id));
    }

    #[test]
    fn imdsv2_enforced_is_clean() {
        let tf = r#"
resource "aws_instance" "ok" {
  metadata_options { http_tokens = "required" }
}
"#;
        let f = evaluate("ec2.tf", tf);
        assert!(!f.iter().any(|x| x.policy.id == IMDSV1.id));
    }
}
