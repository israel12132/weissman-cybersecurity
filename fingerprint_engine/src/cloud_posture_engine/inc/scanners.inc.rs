// ─── IAM / CIEM ────────────────────────────────────────────────────────────────

async fn scan_iam(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    use aws_sdk_iam::types::{StatusType, SummaryKeyType};
    let iam = aws_sdk_iam::Client::new(sdk);
    let mut findings = Vec::new();
    let c_root = ComplianceRef {
        cis: "1.4",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let c_mfa = ComplianceRef {
        cis: "1.5",
        soc2: "CC6.1",
        iso27001: "A.9.4.2",
        pci: "8.3.1",
        nist: "PR.AC-7",
        gdpr: "Art.32",
    };
    let c_pwd = ComplianceRef {
        cis: "1.8",
        soc2: "CC6.1",
        iso27001: "A.9.4.3",
        pci: "8.2.3",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    if opts.check_root_account {
        if let Ok(out) = iam.get_account_summary().send().await {
            if let Some(m) = out.summary_map() {
                let get = |k: &SummaryKeyType| m.get(k).copied().unwrap_or(0);
                if get(&SummaryKeyType::AccountMfaEnabled) == 0 {
                    graph.upsert("aws:account:root", "identity", "global", "privileged", &["no_root_mfa"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_root_no_mfa",
                        "Root account MFA is not enabled",
                        "critical",
                        "T1078.004",
                        &c_mfa,
                        target,
                        0.97,
                        "The AWS account root user has no MFA device. Root has unrestricted access; a stolen root password is full-account compromise.",
                        "Enable hardware/virtual MFA on the root user immediately. Prefer eliminating day-to-day root use entirely.",
                        Evidence::new()
                            .with("account_mfa_enabled", false)
                            .check("get_account_summary.AccountMFAEnabled", true, 0),
                        "aws_account",
                        "root",
                        "global",
                    ));
                }
                let root_keys = get(&SummaryKeyType::AccountAccessKeysPresent);
                if root_keys > 0 {
                    graph.upsert("aws:account:root", "identity", "global", "privileged", &["root_access_keys"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_root_access_keys",
                        "Root account has active access keys",
                        "critical",
                        "T1078.004",
                        &c_root,
                        target,
                        0.97,
                        "Long-lived root access keys exist. Delete root keys entirely; use IAM roles/users for programmatic access.",
                        "Delete all root access keys. Use IAM roles with least privilege for automation.",
                        Evidence::new()
                            .with("root_access_keys_present", true)
                            .check("get_account_summary.AccountAccessKeysPresent", true, root_keys),
                        "aws_account",
                        "root",
                        "global",
                    ));
                }
            }
        }
    }

    if opts.check_password_policy {
        match iam.get_account_password_policy().send().await {
            Ok(out) => {
                if let Some(pp) = out.password_policy() {
                    let min_len = pp.minimum_password_length().unwrap_or(0);
                    if min_len < 14 {
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_weak_password_length",
                            "Weak IAM password policy — minimum length",
                            "medium",
                            "T1110",
                            &c_pwd,
                            target,
                            0.9,
                            &format!("IAM password minimum length is {min_len} (CIS AWS Foundations requires ≥ 14)."),
                            "Set minimum_password_length to at least 14 and require all character classes.",
                            Evidence::new().with("minimum_password_length", min_len),
                            "aws_account",
                            "password_policy",
                            "global",
                        ));
                    }
                }
            }
            Err(e) => {
                let code = e.as_service_error().and_then(|se| se.meta().code()).unwrap_or("");
                if code == "NoSuchEntity" {
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_no_password_policy",
                        "No IAM account password policy configured",
                        "medium",
                        "T1110",
                        &c_pwd,
                        target,
                        0.9,
                        "The account has no IAM password policy, so console users can set trivially weak passwords.",
                        "Create an account password policy with length ≥ 14, complexity, and reuse prevention ≥ 24.",
                        Evidence::new().check("get_account_password_policy", false, "NoSuchEntity"),
                        "aws_account",
                        "password_policy",
                        "global",
                    ));
                }
            }
        }
    }

    let c_user_mfa = ComplianceRef {
        cis: "1.10",
        soc2: "CC6.1",
        iso27001: "A.9.4.2",
        pci: "8.3.1",
        nist: "PR.AC-7",
        gdpr: "Art.32",
    };
    let c_admin = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };
    let c_stale_key = ComplianceRef {
        cis: "1.14",
        soc2: "CC6.1",
        iso27001: "A.9.4.3",
        pci: "8.2.4",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    if let Ok(out) = iam.list_users().send().await {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .unwrap_or(0);
        let max_age = i64::try_from(opts.access_key_max_age_days).unwrap_or(90);
        for u in out.users().iter().take(opts.max_users()) {
            let name = u.user_name().to_string();
            let node_id = format!("aws:iam:user:{name}");
            graph.upsert(&node_id, "iam_user", "global", "internal", &[]);

            let has_console = iam.get_login_profile().user_name(&name).send().await.is_ok();
            if has_console {
                let mfa_empty = iam
                    .list_mfa_devices()
                    .user_name(&name)
                    .send()
                    .await
                    .map(|r| r.mfa_devices().is_empty())
                    .unwrap_or(false);
                if mfa_empty {
                    graph.upsert(&node_id, "iam_user", "global", "internal", &["console_no_mfa"]);
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_console_user_no_mfa",
                        &format!("IAM console user without MFA: {name}"),
                        "high",
                        "T1078.004",
                        &c_user_mfa,
                        target,
                        0.92,
                        &format!("IAM user '{name}' has console access but no MFA device (CIS 1.10)."),
                        "Enforce MFA for all console users via an IAM policy or AWS Organizations SCP.",
                        Evidence::new()
                            .with("user", name.clone())
                            .check("list_mfa_devices", true, "empty"),
                        "iam_user",
                        &name,
                        "global",
                    ));
                }
            }

            if let Ok(keys) = iam.list_access_keys().user_name(&name).send().await {
                for k in keys.access_key_metadata() {
                    if !matches!(k.status(), Some(StatusType::Active)) {
                        continue;
                    }
                    if let Some(created) = k.create_date() {
                        let age_days = (now - created.secs()).max(0) / 86_400;
                        if age_days > max_age {
                            graph.upsert(&node_id, "iam_user", "global", "internal", &["stale_access_key"]);
                            findings.push(posture_finding(
                                Domain::Identity,
                                "iam_stale_access_key",
                                &format!("Stale IAM access key: {name}"),
                                "medium",
                                "T1552.001",
                                &c_stale_key,
                                target,
                                0.88,
                                &format!("Active access key for '{name}' is {age_days} days old (threshold {max_age})."),
                                "Rotate the access key and prefer IAM roles / SSO for programmatic access.",
                                Evidence::new()
                                    .with("user", name.clone())
                                    .with("key_age_days", age_days)
                                    .with("access_key_id", k.access_key_id().unwrap_or("")),
                                "iam_user",
                                &name,
                                "global",
                            ));
                        }
                    }
                }
            }

            if let Ok(att) = iam.list_attached_user_policies().user_name(&name).send().await {
                for p in att.attached_policies() {
                    let arn = p.policy_arn().unwrap_or("");
                    if arn.ends_with(":policy/AdministratorAccess") {
                        graph.upsert(&node_id, "iam_user", "global", "privileged", &["administrator_access"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_direct_admin_policy",
                            &format!("AdministratorAccess attached directly to user: {name}"),
                            "high",
                            "T1098",
                            &c_admin,
                            target,
                            0.92,
                            &format!("User '{name}' has AWS-managed AdministratorAccess attached directly."),
                            "Remove direct admin attachment; grant admin via a group/role with break-glass controls.",
                            Evidence::new().with("user", name.clone()).with("policy_arn", arn),
                            "iam_user",
                            &name,
                            "global",
                        ));
                    }
                }
            }
        }
    }

    if opts.check_iam_wildcards {
        let c_wild = ComplianceRef {
            cis: "1.16",
            soc2: "CC6.3",
            iso27001: "A.9.2.3",
            pci: "7.1.2",
            nist: "PR.AC-4",
            gdpr: "Art.32",
        };
        let mut policy_count = 0usize;
        let mut pag = iam
            .list_policies()
            .scope(aws_sdk_iam::types::PolicyScopeType::Local)
            .only_attached(true)
            .into_paginator()
            .send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for pol in page.policies() {
                if policy_count >= opts.max_resources_per_service {
                    break;
                }
                policy_count += 1;
                let arn = pol.arn().unwrap_or("").to_string();
                let name = pol.policy_name().unwrap_or("").to_string();
                let Some(default_ver) = pol.default_version_id() else {
                    continue;
                };
                let Ok(ver) = iam
                    .get_policy_version()
                    .policy_arn(&arn)
                    .version_id(default_ver)
                    .send()
                    .await
                else {
                    continue;
                };
                let Some(doc) = ver.policy_version().and_then(|pv| pv.document()) else {
                    continue;
                };
                let doc_decoded = urlencoding::decode(doc)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| doc.to_string());
                let doc_l = doc_decoded.to_ascii_lowercase();
                let wildcard_action = doc_l.contains("\"action\":\"*\"")
                    || doc_l.contains("\"action\":[\"*\"]")
                    || doc_l.contains("\"action\":\"*:*\"")
                    || doc_l.contains("\"action\":[\"*:*\"]");
                let wildcard_resource = doc_l.contains("\"resource\":\"*\"")
                    || doc_l.contains("\"resource\":[\"*\"]");
                if wildcard_action || wildcard_resource {
                    graph.upsert(
                        &format!("aws:iam:policy:{name}"),
                        "iam_policy",
                        "global",
                        "privileged",
                        &["wildcard_policy"],
                    );
                    findings.push(posture_finding(
                        Domain::Identity,
                        "iam_wildcard_policy",
                        &format!("Overly permissive IAM policy: {name}"),
                        if wildcard_action { "critical" } else { "high" },
                        "T1098",
                        &c_wild,
                        target,
                        0.9,
                        &format!(
                            "Policy '{name}' allows wildcard Action or Resource — violates least-privilege (CIS 1.16)."
                        ),
                        "Replace wildcard permissions with explicit actions/resources scoped to the minimum required.",
                        Evidence::new()
                            .with("policy_arn", arn.clone())
                            .with("wildcard_action", wildcard_action)
                            .with("wildcard_resource", wildcard_resource),
                        "iam_policy",
                        &name,
                        "global",
                    ));
                }
            }
        }
    }

    findings
}

// ─── S3 data security ──────────────────────────────────────────────────────────

async fn scan_s3(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    home_region: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.1.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    let global = aws_sdk_s3::config::Builder::from(sdk)
        .region(Region::new(home_region.to_string()))
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(global);
    let buckets = match s3.list_buckets().send().await {
        Ok(b) => b,
        Err(e) => {
            findings.push(posture_finding(
                Domain::Data,
                "s3_list_denied",
                "S3 ListBuckets denied",
                "info",
                "",
                &ComplianceRef {
                    cis: "",
                    soc2: "",
                    iso27001: "",
                    pci: "",
                    nist: "",
                    gdpr: "",
                },
                target,
                1.0,
                &format!("s3:ListAllMyBuckets failed ({e}); grant the scanner read-only S3 permissions."),
                "Attach a read-only policy with s3:ListAllMyBuckets and GetBucket* actions.",
                Evidence::new().with("error", e.to_string()),
                "s3",
                "*",
                "global",
            ));
            return findings;
        }
    };

    for b in buckets.buckets().iter().take(opts.max_buckets()) {
        let name = b.name().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let node_id = format!("aws:s3:bucket:{name}");
        graph.upsert(&node_id, "s3_bucket", "pending", "internal", &[]);

        let loc = s3
            .get_bucket_location()
            .bucket(&name)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|x| x.as_str().to_string()));
        let region = map_bucket_location(loc.as_deref());
        let regional = aws_sdk_s3::config::Builder::from(sdk)
            .region(Region::new(region.clone()))
            .build();
        let rs3 = aws_sdk_s3::Client::from_conf(regional);

        let mut public_reason: Option<String> = None;
        match rs3.get_public_access_block().bucket(&name).send().await {
            Ok(resp) => {
                if let Some(pab) = resp.public_access_block_configuration() {
                    let weak = [
                        (pab.block_public_acls(), "block_public_acls=false"),
                        (pab.ignore_public_acls(), "ignore_public_acls=false"),
                        (pab.block_public_policy(), "block_public_policy=false"),
                        (pab.restrict_public_buckets(), "restrict_public_buckets=false"),
                    ];
                    for (flag, label) in weak {
                        if flag == Some(false) {
                            public_reason = Some(label.to_string());
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let missing = e.as_service_error().and_then(|se| se.meta().code())
                    == Some("NoSuchPublicAccessBlockConfiguration");
                if missing {
                    public_reason = Some("no PublicAccessBlock configured".to_string());
                }
            }
        }

        let mut acl_public: Option<String> = None;
        if let Ok(acl) = rs3.get_bucket_acl().bucket(&name).send().await {
            for g in acl.grants() {
                let uri = g
                    .grantee()
                    .and_then(|gg| gg.uri())
                    .unwrap_or("")
                    .to_lowercase();
                if uri.contains("allusers") || uri.contains("authenticatedusers") {
                    acl_public = Some(uri);
                    break;
                }
            }
        }

        if let Some(uri) = acl_public {
            graph.upsert(&node_id, "s3_bucket", &region, "internet", &["public_acl"]);
            findings.push(posture_finding(
                Domain::Data,
                "s3_public_acl",
                &format!("S3 bucket world-readable via ACL: {name}"),
                "critical",
                "T1530",
                &c_public,
                target,
                0.94,
                &format!("Bucket '{name}' ({region}) grants access to a public grantee ({uri})."),
                "Remove public ACL grants; enable S3 Block Public Access at account and bucket level.",
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("public_grantee", uri),
                "s3_bucket",
                &name,
                &region,
            ));
        } else if let Some(reason) = public_reason {
            graph.upsert(&node_id, "s3_bucket", &region, "internet", &["weak_public_access_block"]);
            findings.push(posture_finding(
                Domain::Data,
                "s3_weak_public_access_block",
                &format!("S3 bucket missing public-access protection: {name}"),
                "high",
                "T1530",
                &c_public,
                target,
                0.86,
                &format!("Bucket '{name}' ({region}) does not fully block public access ({reason})."),
                "Enable all four S3 Block Public Access settings on the bucket and account.",
                Evidence::new().with("bucket", name.clone()).with("reason", reason),
                "s3_bucket",
                &name,
                &region,
            ));
        }

        if let Err(e) = rs3.get_bucket_encryption().bucket(&name).send().await {
            let code = e.as_service_error().and_then(|se| se.meta().code()).unwrap_or("");
            if code == "ServerSideEncryptionConfigurationNotFoundError" {
                graph.upsert(&node_id, "s3_bucket", &region, "internal", &["no_default_encryption"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "s3_no_default_encryption",
                    &format!("S3 bucket without default encryption: {name}"),
                    "medium",
                    "T1530",
                    &c_encrypt,
                    target,
                    0.85,
                    &format!("Bucket '{name}' ({region}) has no default server-side encryption."),
                    "Enable default SSE-S3 or SSE-KMS on the bucket.",
                    Evidence::new().with("bucket", name.clone()),
                    "s3_bucket",
                    &name,
                    &region,
                ));
            }
        }

        if opts.check_s3_policy_public {
            if let Ok(pol_resp) = rs3.get_bucket_policy().bucket(&name).send().await {
                if let Some(policy) = pol_resp.policy() {
                    let lower = policy.to_ascii_lowercase();
                    let wildcard_principal = lower.contains("\"principal\":\"*\"")
                        || lower.contains("\"principal\": \"*\"")
                        || lower.contains("\"aws\":\"*\"")
                        || lower.contains("allusers");
                    let allows_read = lower.contains("\"effect\":\"allow\"")
                        || lower.contains("\"effect\": \"allow\"");
                    let s3_read = lower.contains("s3:getobject")
                        || lower.contains("s3:listbucket")
                        || lower.contains("\"s3:*\"")
                        || lower.contains("\"action\":\"*\"")
                        || lower.contains("\"action\":[\"*\"]");
                    if wildcard_principal && allows_read && s3_read {
                        graph.upsert(&node_id, "s3_bucket", &region, "internet", &["public_bucket_policy"]);
                        findings.push(posture_finding(
                            Domain::Data,
                            "s3_public_bucket_policy",
                            &format!("S3 bucket world-readable via bucket policy: {name}"),
                            "critical",
                            "T1530",
                            &c_public,
                            target,
                            0.95,
                            &format!(
                                "Bucket '{name}' ({region}) bucket policy grants public read/list to anonymous or wildcard principals."
                            ),
                            "Remove wildcard principals from the bucket policy; enforce Block Public Access at account level.",
                            Evidence::new()
                                .with("bucket", name.clone())
                                .with("policy_excerpt", &policy[..policy.len().min(512)]),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
            }
        }

        if opts.check_s3_versioning {
            if let Ok(ver) = rs3.get_bucket_versioning().bucket(&name).send().await {
                let enabled = ver
                    .status()
                    .map(|s| s.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("Enabled"));
                if !enabled {
                    graph.upsert(&node_id, "s3_bucket", &region, "internal", &["no_versioning"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "s3_versioning_disabled",
                        &format!("S3 bucket versioning disabled: {name}"),
                        "medium",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.82,
                        &format!("Bucket '{name}' ({region}) has no versioning — ransomware or accidental delete is irreversible."),
                        "Enable S3 versioning and lifecycle rules; pair with MFA Delete for critical buckets.",
                        Evidence::new().with("bucket", name.clone()),
                        "s3_bucket",
                        &name,
                        &region,
                    ));
                }
            }
        }

        if opts.check_s3_object_lock {
            match rs3.get_object_lock_configuration().bucket(&name).send().await {
                Ok(cfg) => {
                    let enabled = cfg
                        .object_lock_configuration()
                        .and_then(|c| c.object_lock_enabled())
                        .map(|s| s.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case("Enabled"));
                    if !enabled {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "s3_object_lock_disabled",
                            &format!("S3 bucket without Object Lock governance: {name}"),
                            "medium",
                            "T1485",
                            &c_encrypt,
                            target,
                            0.84,
                            &format!(
                                "Bucket '{name}' ({region}) has Object Lock disabled — WORM/immutable compliance unavailable."
                            ),
                            "Enable Object Lock in COMPLIANCE or GOVERNANCE mode on regulated buckets.",
                            Evidence::new().with("bucket", name.clone()),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
                Err(e) => {
                    let missing = e.as_service_error().and_then(|se| se.meta().code())
                        == Some("ObjectLockConfigurationNotFoundError");
                    if missing {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "s3_no_object_lock",
                            &format!("S3 bucket has no Object Lock configuration: {name}"),
                            "low",
                            "T1485",
                            &c_encrypt,
                            target,
                            0.78,
                            &format!(
                                "Bucket '{name}' ({region}) has no Object Lock — cannot enforce immutable retention."
                            ),
                            "Enable Object Lock at bucket creation for regulated data.",
                            Evidence::new().with("bucket", name.clone()),
                            "s3_bucket",
                            &name,
                            &region,
                        ));
                    }
                }
            }
        }
    }

    findings
}

async fn scan_ec2_vpc(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_sg = ComplianceRef {
        cis: "5.2",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.2",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_imds = ComplianceRef {
        cis: "5.6",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.7",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_flow = ComplianceRef {
        cis: "3.9",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "DE.AE-3",
        gdpr: "Art.32",
    };
    let c_ebs = ComplianceRef {
        cis: "2.2.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec2 = aws_sdk_ec2::Client::from_conf(
            aws_sdk_ec2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );

        let mut sg_count = 0usize;
        let mut sg_pag = ec2.describe_security_groups().into_paginator().send();
        while let Some(page) = sg_pag.next().await {
            let Ok(page) = page else { break };
            for sg in page.security_groups() {
                if sg_count >= opts.max_resources_per_service {
                    break;
                }
                sg_count += 1;
                let sg_id = sg.group_id().unwrap_or("").to_string();
                let sg_name = sg.group_name().unwrap_or("").to_string();
                let sg_node = format!("aws:ec2:sg:{sg_id}");
                graph.upsert(&sg_node, "security_group", r, "internal", &[]);
                let mut sg_open_world = false;

                for perm in sg.ip_permissions() {
                    let proto = perm.ip_protocol().unwrap_or("-1");
                    let open_world = perm
                        .ip_ranges()
                        .iter()
                        .any(|ipr| ipr.cidr_ip() == Some("0.0.0.0/0"));
                    if !open_world {
                        continue;
                    }
                    sg_open_world = true;
                    let all_traffic = proto == "-1";
                    if !all_traffic && !port_in_dangerous(perm.from_port(), perm.to_port()) {
                        continue;
                    }
                    let sev = if all_traffic { "critical" } else { "high" };
                    graph.upsert(&sg_node, "security_group", r, "internet", &["open_ingress"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "ec2_sg_open_ingress",
                        &format!("Security group open to the internet: {sg_id}"),
                        sev,
                        "T1190",
                        &c_sg,
                        target,
                        0.91,
                        &format!("Security group {sg_id} in {r} allows ingress from 0.0.0.0/0."),
                        "Restrict ingress to known CIDRs, a bastion host, or VPN-only access.",
                        Evidence::new()
                            .with("security_group", sg_id.clone())
                            .with("protocol", proto)
                            .with("from_port", perm.from_port().unwrap_or(-1))
                            .with("to_port", perm.to_port().unwrap_or(-1)),
                        "ec2_security_group",
                        &sg_id,
                        r,
                    ));
                }

                if opts.check_default_sg && sg_name == "default" && sg_open_world {
                    graph.upsert(&sg_node, "security_group", r, "internet", &["default_sg_open"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "ec2_default_sg_open",
                        &format!("Default VPC security group allows world ingress: {sg_id}"),
                        "high",
                        "T1190",
                        &c_sg,
                        target,
                        0.9,
                        &format!("Default security group {sg_id} in {r} permits 0.0.0.0/0 ingress — AWS best practice is to block all traffic on the default SG."),
                        "Remove all inbound/outbound rules from the default SG; attach purpose-built groups to instances.",
                        Evidence::new().with("security_group", sg_id.clone()).with("group_name", "default"),
                        "ec2_security_group",
                        &sg_id,
                        r,
                    ));
                }
            }
        }

        if opts.check_imds {
            let mut inst_count = 0usize;
            let mut inst_pag = ec2.describe_instances().into_paginator().send();
            while let Some(page) = inst_pag.next().await {
                let Ok(page) = page else { break };
                for res in page.reservations() {
                    for inst in res.instances() {
                        if inst_count >= opts.max_resources_per_service {
                            break;
                        }
                        inst_count += 1;
                        let iid = inst.instance_id().unwrap_or("").to_string();
                        let inst_node = format!("aws:ec2:instance:{iid}");
                        let public_ip = inst.public_ip_address().map(str::to_string);
                        let exposure = if public_ip.is_some() { "internet" } else { "internal" };
                        graph.upsert(&inst_node, "ec2_instance", r, exposure, &[]);

                        let imdsv1 = inst
                            .metadata_options()
                            .and_then(|m| m.http_tokens())
                            .map(|t| t.as_str().eq_ignore_ascii_case("optional"))
                            .unwrap_or(false);
                        let has_profile = inst.iam_instance_profile().is_some();
                        if let Some(profile) = inst.iam_instance_profile() {
                            if let Some(arn) = profile.arn() {
                                graph.link(&inst_node, arn, "assumes_role");
                                graph.upsert(arn, "iam_instance_profile", r, exposure, &[]);
                            }
                        }

                        if public_ip.is_some() && imdsv1 {
                            let sev = if has_profile { "high" } else { "medium" };
                            graph.upsert(&inst_node, "ec2_instance", r, "internet", &["imdsv1", "public_ip"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "ec2_imdsv1_public",
                                &format!("Public EC2 instance allows IMDSv1: {iid}"),
                                sev,
                                "T1552.005",
                                &c_imds,
                                target,
                                0.89,
                                &format!("Instance {iid} ({r}) has a public IP and permits IMDSv1 — SSRF can steal instance-role credentials."),
                                "Set HttpTokens=required (IMDSv2 only) and prefer private subnets with egress via NAT.",
                                Evidence::new()
                                    .with("instance_id", iid.clone())
                                    .with("public_ip", public_ip.unwrap_or_default())
                                    .with("imdsv1_allowed", true)
                                    .with("has_instance_role", has_profile),
                                "ec2_instance",
                                &iid,
                                r,
                            ));
                        }
                    }
                }
            }
        }

        let mut vol_count = 0usize;
        let mut vol_pag = ec2.describe_volumes().into_paginator().send();
        while let Some(page) = vol_pag.next().await {
            let Ok(page) = page else { break };
            for v in page.volumes() {
                if vol_count >= opts.max_resources_per_service {
                    break;
                }
                vol_count += 1;
                if v.encrypted() == Some(false) {
                    let vid = v.volume_id().unwrap_or("").to_string();
                    graph.upsert(&format!("aws:ebs:volume:{vid}"), "ebs_volume", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "ebs_unencrypted",
                        &format!("Unencrypted EBS volume: {vid}"),
                        "medium",
                        "T1530",
                        &c_ebs,
                        target,
                        0.84,
                        &format!("EBS volume {vid} in {r} is not encrypted at rest."),
                        "Enable EBS encryption by default in the region and encrypt existing volumes.",
                        Evidence::new().with("volume_id", vid.clone()),
                        "ebs_volume",
                        &vid,
                        r,
                    ));
                }
            }
        }

        if opts.check_flow_logs {
            let fl = ec2.describe_flow_logs().send().await;
            let has_flow = fl
                .ok()
                .map(|r| !r.flow_logs().is_empty())
                .unwrap_or(false);
            if !has_flow {
                findings.push(posture_finding(
                    Domain::Governance,
                    "vpc_no_flow_logs",
                    &format!("No VPC flow logs enabled in {r}"),
                    "medium",
                    "T1046",
                    &c_flow,
                    target,
                    0.8,
                    &format!("Region {r} has no VPC flow logs — network visibility and forensics are blind."),
                    "Enable VPC Flow Logs on all VPCs and ship to CloudWatch Logs or S3.",
                    Evidence::new().check("describe_flow_logs", true, "empty"),
                    "vpc",
                    "*",
                    r,
                ));
            }
        }

        if opts.check_public_snapshots {
            let mut snap_count = 0usize;
            let mut snap_pag = ec2
                .describe_snapshots()
                .owner_ids("self")
                .into_paginator()
                .send();
            while let Some(page) = snap_pag.next().await {
                let Ok(page) = page else { break };
                for snap in page.snapshots() {
                    if snap_count >= opts.max_resources_per_service {
                        break;
                    }
                    snap_count += 1;
                    let sid = snap.snapshot_id().unwrap_or("").to_string();
                    if sid.is_empty() {
                        continue;
                    }
                    let public = ec2
                        .describe_snapshot_attribute()
                        .snapshot_id(&sid)
                        .attribute(aws_sdk_ec2::types::SnapshotAttributeName::CreateVolumePermission)
                        .send()
                        .await
                        .ok()
                        .map(|attr| {
                            attr.create_volume_permissions().iter().any(|p| {
                                matches!(
                                    p.group(),
                                    Some(aws_sdk_ec2::types::PermissionGroup::All)
                                )
                            })
                        })
                        .unwrap_or(false);
                    if !public {
                        continue;
                    }
                    let sid = snap.snapshot_id().unwrap_or("").to_string();
                    let node_id = format!("aws:ebs:snapshot:{sid}");
                    graph.upsert(&node_id, "ebs_snapshot", r, "internet", &["public_snapshot"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "ebs_public_snapshot",
                        &format!("Public EBS snapshot: {sid}"),
                        "critical",
                        "T1530",
                        &c_ebs,
                        target,
                        0.93,
                        &format!(
                            "EBS snapshot {sid} in {r} is shared with group 'all' — any AWS account can create volumes from it."
                        ),
                        "Remove public snapshot permissions; use encrypted snapshots with IAM-scoped sharing only.",
                        Evidence::new().with("snapshot_id", sid.clone()),
                        "ebs_snapshot",
                        &sid,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── SSM governance ────────────────────────────────────────────────────────────

async fn scan_ssm(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if !opts.check_ssm_public_params {
        return findings;
    }
    let c_ssm = ComplianceRef {
        cis: "3.2",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ssm = aws_sdk_ssm::Client::from_conf(
            aws_sdk_ssm::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ssm.describe_parameters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for p in page.parameters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = p.name().unwrap_or("").to_string();
                if name.starts_with("/aws/service/") {
                    continue;
                }
                let tier = p.tier().map(|t| t.as_str()).unwrap_or("");
                if tier.eq_ignore_ascii_case("Advanced") {
                    continue;
                }
                let node_id = format!("aws:ssm:param:{name}");
                graph.upsert(&node_id, "ssm_parameter", r, "internal", &[]);

                if let Ok(detail) = ssm.get_parameter().name(&name).with_decryption(false).send().await {
                    let param_type = detail.parameter().and_then(|pp| pp.r#type()).map(|t| t.as_str()).unwrap_or("");
                    if param_type.eq_ignore_ascii_case("String") {
                        graph.upsert(&node_id, "ssm_parameter", r, "internet", &["public_string_param"]);
                        findings.push(posture_finding(
                            Domain::Governance,
                            "ssm_public_string_param",
                            &format!("SSM String parameter (potentially public): {name}"),
                            "medium",
                            "T1552.001",
                            &c_ssm,
                            target,
                            0.75,
                            &format!("SSM parameter '{name}' in {r} is type String — verify it is not exposed via overly broad IAM."),
                            "Use SecureString for secrets; restrict ssm:GetParameter with resource-level IAM conditions.",
                            Evidence::new().with("parameter", name.clone()).with("type", param_type),
                            "ssm_parameter",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── Lambda serverless posture ─────────────────────────────────────────────────

async fn scan_lambda(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_secrets = ComplianceRef {
        cis: "3.4",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let lambda = aws_sdk_lambda::Client::from_conf(
            aws_sdk_lambda::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = lambda.list_functions().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for func in page.functions() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = func.function_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let _arn = func.function_arn().unwrap_or("").to_string();
                let node_id = format!("aws:lambda:function:{name}");
                graph.upsert(&node_id, "lambda_function", r, "internal", &[]);

                if let Some(role) = func.role() {
                    graph.link(&node_id, role, "execution_role");
                    graph.upsert(role, "iam_role", r, "internal", &[]);
                }

                if let Ok(pol) = lambda.get_policy().function_name(&name).send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        let public_invoke = lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"principal\": \"*\"")
                            || lower.contains("\"aws\":\"*\"");
                        if public_invoke {
                            graph.upsert(&node_id, "lambda_function", r, "internet", &["public_invoke"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "lambda_public_resource_policy",
                                &format!("Lambda function publicly invokable: {name}"),
                                "critical",
                                "T1190",
                                &c_public,
                                target,
                                0.93,
                                &format!(
                                    "Function '{name}' ({r}) has a resource-based policy allowing unauthenticated invocation."
                                ),
                                "Remove wildcard principals from the function resource policy; use IAM auth or API Gateway with authorizers.",
                                Evidence::new().with("function", name.clone()).with("policy_excerpt", &raw[..raw.len().min(512)]),
                                "lambda_function",
                                &name,
                                r,
                            ));
                        }
                    }
                }

                if let Ok(cfg) = lambda.get_function_configuration().function_name(&name).send().await {
                    let env_vars = cfg
                        .environment()
                        .and_then(|e| e.variables())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    if env_vars > 0 {
                        let suspicious = ["password", "secret", "api_key", "apikey", "token", "private_key"];
                        if let Some(vars) = cfg.environment().and_then(|e| e.variables()) {
                            for (k, _v) in vars {
                                let kl = k.to_ascii_lowercase();
                                if suspicious.iter().any(|s| kl.contains(s)) {
                                    graph.upsert(&node_id, "lambda_function", r, "internal", &["env_secrets"]);
                                    findings.push(posture_finding(
                                        Domain::Governance,
                                        "lambda_env_secret_key",
                                        &format!("Lambda environment variable name suggests a secret: {name}"),
                                        "high",
                                        "T1552.001",
                                        &c_secrets,
                                        target,
                                        0.82,
                                        &format!(
                                            "Function '{name}' ({r}) defines environment variable '{k}' — secrets in plain env vars are visible to anyone with lambda:GetFunctionConfiguration."
                                        ),
                                        "Store secrets in AWS Secrets Manager or SSM Parameter Store (SecureString); reference by ARN at runtime.",
                                        Evidence::new().with("function", name.clone()).with("env_key", k.clone()),
                                        "lambda_function",
                                        &name,
                                        r,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }

                if opts.check_lambda_urls {
                    if let Ok(url_cfg) = lambda.get_function_url_config().function_name(&name).send().await {
                        let auth = url_cfg.auth_type().as_str();
                        if auth.eq_ignore_ascii_case("NONE") {
                            graph.upsert(&node_id, "lambda_function", r, "internet", &["function_url_public"]);
                            findings.push(posture_finding(
                                Domain::Compute,
                                "lambda_function_url_no_auth",
                                &format!("Lambda Function URL without auth: {name}"),
                                "critical",
                                "T1190",
                                &c_public,
                                target,
                                0.94,
                                &format!(
                                    "Function '{name}' ({r}) exposes a Function URL with AuthType=NONE — unauthenticated HTTP access."
                                ),
                                "Set AuthType=AWS_IAM or front with Amazon CloudFront + WAF; disable the URL if unused.",
                                Evidence::new()
                                    .with("function", name.clone())
                                    .with("function_url", url_cfg.function_url()),
                                "lambda_function",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── RDS data-store posture ────────────────────────────────────────────────────

async fn scan_rds(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let rds = aws_sdk_rds::Client::from_conf(
            aws_sdk_rds::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = rds.describe_db_instances().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for db in page.db_instances() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = db.db_instance_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:rds:instance:{id}");
                let exposure = if db.publicly_accessible() == Some(true) {
                    "internet"
                } else {
                    "internal"
                };
                graph.upsert(&node_id, "rds_instance", r, exposure, &[]);

                if db.publicly_accessible() == Some(true) {
                    graph.upsert(&node_id, "rds_instance", r, "internet", &["public_rds"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "rds_publicly_accessible",
                        &format!("RDS instance publicly accessible: {id}"),
                        "critical",
                        "T1190",
                        &c_public,
                        target,
                        0.94,
                        &format!(
                            "RDS instance '{id}' ({r}) has publicly_accessible=true — databases reachable from the internet."
                        ),
                        "Set publicly_accessible=false; place RDS in private subnets with security-group restrictions.",
                        Evidence::new()
                            .with("db_instance", id.clone())
                            .with("engine", db.engine().unwrap_or(""))
                            .with("endpoint", db.endpoint().and_then(|e| e.address()).unwrap_or("")),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }

                if db.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "rds_instance", r, exposure, &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "rds_unencrypted_storage",
                        &format!("RDS storage not encrypted: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.88,
                        &format!("RDS instance '{id}' ({r}) does not have storage encryption enabled."),
                        "Enable storage_encrypted on new instances; migrate existing data to encrypted snapshots.",
                        Evidence::new().with("db_instance", id.clone()),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }

                if db.backup_retention_period().unwrap_or(0) < 7 {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "rds_short_backup_retention",
                        &format!("RDS backup retention below 7 days: {id}"),
                        "medium",
                        "T1485",
                        &ComplianceRef {
                            cis: "2.3.1",
                            soc2: "CC7.2",
                            iso27001: "A.12.3.1",
                            pci: "9.5.1",
                            nist: "PR.IP-4",
                            gdpr: "Art.32",
                        },
                        target,
                        0.8,
                        &format!(
                            "RDS instance '{id}' ({r}) has backup retention of {} day(s) (CIS recommends ≥ 7).",
                            db.backup_retention_period().unwrap_or(0)
                        ),
                        "Increase backup_retention_period to at least 7 days; enable automated backups.",
                        Evidence::new().with("backup_retention_days", db.backup_retention_period().unwrap_or(0)),
                        "rds_instance",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── KMS key governance ────────────────────────────────────────────────────────

async fn scan_kms(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_rotation = ComplianceRef {
        cis: "3.8",
        soc2: "CC6.1",
        iso27001: "A.10.1.2",
        pci: "3.6.4",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    let c_public = ComplianceRef {
        cis: "3.8",
        soc2: "CC6.6",
        iso27001: "A.9.4.1",
        pci: "3.5.1",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let kms = aws_sdk_kms::Client::from_conf(
            aws_sdk_kms::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = kms.list_keys().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for key in page.keys() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                let key_id = key.key_id().unwrap_or("").to_string();
                if key_id.is_empty() {
                    continue;
                }
                count += 1;
                let node_id = format!("aws:kms:key:{key_id}");
                graph.upsert(&node_id, "kms_key", r, "internal", &[]);

                if let Ok(desc) = kms.describe_key().key_id(&key_id).send().await {
                    if let Some(meta) = desc.key_metadata() {
                        let customer_managed = meta
                            .key_manager()
                            .map(|m| *m == aws_sdk_kms::types::KeyManagerType::Customer)
                            .unwrap_or(false);
                        if customer_managed {
                            let rotation_on = kms
                                .get_key_rotation_status()
                                .key_id(&key_id)
                                .send()
                                .await
                                .ok()
                                .map(|s| s.key_rotation_enabled())
                                .unwrap_or(false);
                            if !rotation_on {
                            graph.upsert(&node_id, "kms_key", r, "internal", &["no_rotation"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "kms_rotation_disabled",
                                &format!("Customer-managed KMS key without rotation: {key_id}"),
                                "medium",
                                "T1552.004",
                                &c_rotation,
                                target,
                                0.85,
                                &format!("KMS key '{key_id}' ({r}) is customer-managed but automatic key rotation is disabled."),
                                "Enable automatic key rotation for customer-managed CMKs (annual rotation is free).",
                                Evidence::new().with("key_id", key_id.clone()),
                                "kms_key",
                                &key_id,
                                r,
                            ));
                            }
                        }
                    }
                }

                if let Ok(pol) = kms.get_key_policy().key_id(&key_id).policy_name("default").send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"principal\": \"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&node_id, "kms_key", r, "internet", &["public_key_policy"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "kms_public_key_policy",
                                &format!("KMS key policy allows wildcard principal: {key_id}"),
                                "critical",
                                "T1552.004",
                                &c_public,
                                target,
                                0.92,
                                &format!("KMS key '{key_id}' ({r}) default policy grants access to a wildcard principal."),
                                "Restrict key policy to specific AWS accounts, roles, and services; never use Principal \"*\".",
                                Evidence::new().with("key_id", key_id.clone()).with("policy_excerpt", &raw[..raw.len().min(512)]),
                                "kms_key",
                                &key_id,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── CloudTrail audit logging ──────────────────────────────────────────────────

async fn scan_cloudtrail(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let c_trail = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "DE.AE-3",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ct = aws_sdk_cloudtrail::Client::from_conf(
            aws_sdk_cloudtrail::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );

        let trails = match ct.describe_trails().include_shadow_trails(false).send().await {
            Ok(t) => t.trail_list().to_vec(),
            Err(_) => continue,
        };

        if trails.is_empty() {
            graph.upsert(&format!("aws:cloudtrail:{r}"), "cloudtrail", r, "internal", &["no_trail"]);
            findings.push(posture_finding(
                Domain::Governance,
                "cloudtrail_not_configured",
                &format!("No CloudTrail trail configured in {r}"),
                "high",
                "T1562.008",
                &c_trail,
                target,
                0.9,
                &format!("Region {r} has no CloudTrail trail — API activity is not audited."),
                "Create a multi-region CloudTrail trail logging to a dedicated, encrypted S3 bucket with log file validation.",
                Evidence::new().check("describe_trails", true, "empty"),
                "cloudtrail",
                "*",
                r,
            ));
            continue;
        }

        for trail in trails.iter().take(opts.max_resources_per_service) {
            let name = trail.name().unwrap_or("").to_string();
            let node_id = format!("aws:cloudtrail:trail:{name}");
            graph.upsert(&node_id, "cloudtrail_trail", r, "internal", &[]);

            let status = ct.get_trail_status().name(&name).send().await;
            let logging = status
                .ok()
                .and_then(|s| s.is_logging())
                .unwrap_or(false);
            if !logging {
                graph.upsert(&node_id, "cloudtrail_trail", r, "internal", &["not_logging"]);
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_not_logging",
                    &format!("CloudTrail trail not actively logging: {name}"),
                    "critical",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.95,
                    &format!("Trail '{name}' in {r} exists but IsLogging=false — attackers can operate undetected."),
                    "Start logging on the trail; verify the S3 bucket policy and CloudWatch Logs integration.",
                    Evidence::new().with("trail", name.clone()).check("is_logging", true, false),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }

            if trail.log_file_validation_enabled() != Some(true) {
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_no_log_validation",
                    &format!("CloudTrail log file validation disabled: {name}"),
                    "medium",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.85,
                    &format!("Trail '{name}' ({r}) does not enable log file validation — tampered logs may go undetected."),
                    "Enable log file validation on all CloudTrail trails.",
                    Evidence::new().with("trail", name.clone()),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }

            if trail.is_multi_region_trail() != Some(true) {
                findings.push(posture_finding(
                    Domain::Governance,
                    "cloudtrail_single_region",
                    &format!("CloudTrail trail is single-region: {name}"),
                    "medium",
                    "T1562.008",
                    &c_trail,
                    target,
                    0.8,
                    &format!("Trail '{name}' ({r}) is not multi-region — activity in other regions may be invisible."),
                    "Enable IsMultiRegionTrail on the organisation's primary audit trail.",
                    Evidence::new().with("trail", name.clone()),
                    "cloudtrail_trail",
                    &name,
                    r,
                ));
            }
        }
    }

    findings
}

// ─── IAM roles (CIEM extension) ────────────────────────────────────────────────

async fn scan_iam_roles(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    let iam = aws_sdk_iam::Client::new(sdk);
    let mut findings = Vec::new();
    let c_trust = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };
    let c_admin = ComplianceRef {
        cis: "1.16",
        soc2: "CC6.3",
        iso27001: "A.9.2.3",
        pci: "7.1.2",
        nist: "PR.AC-4",
        gdpr: "Art.32",
    };

    let mut count = 0usize;
    let mut pag = iam.list_roles().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        for role in page.roles() {
            if count >= opts.max_users() {
                break;
            }
            count += 1;
            let name = role.role_name().to_string();
            let arn = role.arn().to_string();
            let node_id = format!("aws:iam:role:{name}");
            graph.upsert(&node_id, "iam_role", "global", "internal", &[]);

            if let Ok(trust) = iam.get_role().role_name(&name).send().await {
                if let Some(doc) = trust.role().and_then(|r| r.assume_role_policy_document()) {
                    let lower = doc.to_ascii_lowercase();
                    // AWS returns URL-encoded JSON; wildcards survive encoding.
                    if lower.contains("\"principal\":\"*\"")
                        || lower.contains("\"aws\":\"*\"")
                        || lower.contains("root")
                    {
                        let sev = if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            "critical"
                        } else {
                            "high"
                        };
                        graph.upsert(&node_id, "iam_role", "global", "internet", &["permissive_trust"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_role_permissive_trust",
                            &format!("IAM role with permissive trust policy: {name}"),
                            sev,
                            "T1098",
                            &c_trust,
                            target,
                            0.9,
                            &format!("Role '{name}' allows assumption by a wildcard or overly broad principal."),
                            "Restrict AssumeRole to specific AWS account IDs and external IDs; remove Principal \"*\".",
                            Evidence::new().with("role", name.clone()).with("trust_excerpt", &doc[..doc.len().min(512)]),
                            "iam_role",
                            &name,
                            "global",
                        ));
                    }
                }
            }

            if let Ok(att) = iam.list_attached_role_policies().role_name(&name).send().await {
                for p in att.attached_policies() {
                    let pol_arn = p.policy_arn().unwrap_or("");
                    if pol_arn.ends_with(":policy/AdministratorAccess") {
                        graph.upsert(&node_id, "iam_role", "global", "privileged", &["administrator_access"]);
                        findings.push(posture_finding(
                            Domain::Identity,
                            "iam_role_admin_policy",
                            &format!("AdministratorAccess attached to role: {name}"),
                            "high",
                            "T1098",
                            &c_admin,
                            target,
                            0.91,
                            &format!("Role '{name}' ({arn}) has AWS-managed AdministratorAccess attached."),
                            "Replace with least-privilege inline/custom policies; use permission boundaries.",
                            Evidence::new().with("role", name.clone()).with("policy_arn", pol_arn),
                            "iam_role",
                            &name,
                            "global",
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── IAM Access Analyzer (external access — Wiz-class zero-trust plane) ────────

async fn scan_access_analyzer(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_access_analyzer {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ext = ComplianceRef {
        cis: "1.22",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let aa = aws_sdk_accessanalyzer::Client::from_conf(
            aws_sdk_accessanalyzer::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let analyzers = match aa.list_analyzers().send().await {
            Ok(a) => a.analyzers().to_vec(),
            Err(_) => continue,
        };
        if analyzers.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "access_analyzer_not_enabled",
                &format!("IAM Access Analyzer not enabled in {r}"),
                "medium",
                "T1580",
                &c_ext,
                target,
                0.85,
                &format!("Region {r} has no Access Analyzer — external-access paths to S3/IAM/Lambda may be invisible."),
                "Enable the account-level or organization-level IAM Access Analyzer in every active region.",
                Evidence::new().check("list_analyzers", true, "empty"),
                "access_analyzer",
                "*",
                r,
            ));
            continue;
        }

        let mut finding_count = 0usize;
        for analyzer in analyzers.iter().take(3) {
            let arn = analyzer.arn();
            let mut pag = aa
                .list_findings()
                .analyzer_arn(arn)
                .max_results(100)
                .into_paginator()
                .send();
            while let Some(page) = pag.next().await {
                let Ok(page) = page else { break };
                for f in page.findings() {
                    if finding_count >= opts.max_resources_per_service {
                        break;
                    }
                    finding_count += 1;
                    let fid = f.id().to_string();
                    let resource = f.resource().unwrap_or("").to_string();
                    let status = f.status().as_str();
                    if !status.eq_ignore_ascii_case("ACTIVE") {
                        continue;
                    }
                    let node_id = format!("aws:resource:{resource}");
                    graph.upsert(&node_id, "external_resource", r, "internet", &["access_analyzer_external"]);
                    let title = format!(
                        "External {} access: {}",
                        f.resource_type().as_str(),
                        resource
                    );
                    let sev = if title.to_ascii_lowercase().contains("public")
                        || title.to_ascii_lowercase().contains("external")
                    {
                        "high"
                    } else {
                        "medium"
                    };
                    findings.push(posture_finding(
                        Domain::Network,
                        "access_analyzer_external_access",
                        &format!("Access Analyzer: {title}"),
                        sev,
                        "T1530",
                        &c_ext,
                        target,
                        0.92,
                        &format!(
                            "IAM Access Analyzer ({r}) flagged active external access to `{resource}` — {title}."
                        ),
                        "Review the resource policy/ACL and remove public or cross-account access; validate with Access Analyzer archive after fix.",
                        Evidence::new()
                            .with("finding_id", fid)
                            .with("resource", resource.clone())
                            .with("analyzer", arn),
                        "access_analyzer_finding",
                        &resource,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── GuardDuty threat-detection plane ──────────────────────────────────────────

async fn scan_guardduty(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_guardduty {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_gd = ComplianceRef {
        cis: "4.15",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.6.1",
        nist: "DE.CM-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let gd = aws_sdk_guardduty::Client::from_conf(
            aws_sdk_guardduty::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let ids = match gd.list_detectors().send().await {
            Ok(d) => d.detector_ids().to_vec(),
            Err(_) => continue,
        };
        if ids.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "guardduty_not_enabled",
                &format!("GuardDuty not enabled in {r}"),
                "high",
                "T1562.001",
                &c_gd,
                target,
                0.9,
                &format!("No GuardDuty detector in {r} — malware, crypto-mining, and IAM anomaly detection are blind."),
                "Enable GuardDuty in all regions; centralize findings to Security Hub.",
                Evidence::new().check("list_detectors", true, "empty"),
                "guardduty",
                "*",
                r,
            ));
            continue;
        }
        for id in ids.iter().take(1) {
            if let Ok(desc) = gd.get_detector().detector_id(id).send().await {
                let status = desc.status().map(|s| s.as_str()).unwrap_or("");
                if !status.eq_ignore_ascii_case("ENABLED") {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "guardduty_disabled",
                        &format!("GuardDuty detector disabled in {r}"),
                        "high",
                        "T1562.001",
                        &c_gd,
                        target,
                        0.9,
                        &format!("GuardDuty detector {id} in {r} is not ENABLED."),
                        "Set detector status to ENABLED and enable S3/EKS/Lambda/RDS protection data sources.",
                        Evidence::new().with("detector_id", id.clone()).with("status", status),
                        "guardduty_detector",
                        id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── AWS Config recorder (drift / compliance plane) ────────────────────────────

async fn scan_config_recorder(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_config_recorder {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_cfg = ComplianceRef {
        cis: "3.5",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.5.1",
        nist: "DE.AE-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let cfg = aws_sdk_config::Client::from_conf(
            aws_sdk_config::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let recs = match cfg.describe_configuration_recorders().send().await {
            Ok(c) => c.configuration_recorders().to_vec(),
            Err(_) => continue,
        };
        if recs.is_empty() {
            findings.push(posture_finding(
                Domain::Governance,
                "config_recorder_missing",
                &format!("AWS Config recorder not configured in {r}"),
                "medium",
                "T1562.008",
                &c_cfg,
                target,
                0.85,
                &format!("No AWS Config recorder in {r} — configuration drift and compliance rules cannot run."),
                "Enable AWS Config recorder with an S3 delivery channel and SNS notifications.",
                Evidence::new().check("describe_configuration_recorders", true, "empty"),
                "config_recorder",
                "*",
                r,
            ));
            continue;
        }
        for rec in recs {
            let name = rec.name().unwrap_or("default").to_string();
            if let Ok(status) = cfg
                .describe_configuration_recorder_status()
                .configuration_recorder_names(&name)
                .send()
                .await
            {
                let recording = status
                    .configuration_recorders_status()
                    .first()
                    .map(|s| s.recording())
                    .unwrap_or(false);
                if !recording {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "config_recorder_not_recording",
                        &format!("AWS Config recorder not recording: {name}"),
                        "high",
                        "T1562.008",
                        &c_cfg,
                        target,
                        0.88,
                        &format!("Config recorder '{name}' in {r} exists but recording=false."),
                        "Start the configuration recorder and verify the delivery channel IAM role.",
                        Evidence::new().with("recorder", name.clone()),
                        "config_recorder",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Account-level S3 public access block ──────────────────────────────────────

async fn scan_account_s3_public_block(
    sdk: &SdkConfig,
    account_id: &str,
    opts: &CloudScanOptions,
    target: &str,
    _graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_account_s3_block || account_id.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_pab = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };
    let s3c = aws_sdk_s3control::Client::from_conf(
        aws_sdk_s3control::config::Builder::from(sdk)
            .region(Region::new("us-east-1".to_string()))
            .build(),
    );
    match s3c
        .get_public_access_block()
        .account_id(account_id)
        .send()
        .await
    {
        Ok(resp) => {
            if let Some(pab) = resp.public_access_block_configuration() {
                let weak = [
                    (pab.block_public_acls(), "BlockPublicAcls"),
                    (pab.ignore_public_acls(), "IgnorePublicAcls"),
                    (pab.block_public_policy(), "BlockPublicPolicy"),
                    (pab.restrict_public_buckets(), "RestrictPublicBuckets"),
                ];
                for (flag, label) in weak {
                    if flag == Some(false) {
                        findings.push(posture_finding(
                            Domain::Data,
                            "account_s3_public_access_block_weak",
                            &format!("Account S3 Block Public Access incomplete: {label}"),
                            "critical",
                            "T1530",
                            &c_pab,
                            target,
                            0.95,
                            &format!(
                                "Account {account_id} has S3 Block Public Access setting `{label}=false` — new buckets can become public."
                            ),
                            "Enable all four account-level S3 Block Public Access settings immediately.",
                            Evidence::new().with("account_id", account_id).with("weak_setting", label),
                            "aws_account",
                            account_id,
                            "global",
                        ));
                        break;
                    }
                }
            }
        }
        Err(e) => {
            let missing = e.as_service_error().and_then(|se| se.meta().code())
                == Some("NoSuchPublicAccessBlockConfiguration");
            if missing {
                findings.push(posture_finding(
                    Domain::Data,
                    "account_s3_no_public_access_block",
                    "Account-level S3 Block Public Access not configured",
                    "critical",
                    "T1530",
                    &c_pab,
                    target,
                    0.94,
                    &format!("Account {account_id} has no account-level S3 Block Public Access — buckets can be made public by default."),
                    "Apply S3 Block Public Access at the account level before any bucket is created.",
                    Evidence::new().check("get_public_access_block", false, "NoSuchPublicAccessBlockConfiguration"),
                    "aws_account",
                    account_id,
                    "global",
                ));
            }
        }
    }

    findings
}

// ─── EKS Kubernetes control plane ──────────────────────────────────────────────

async fn scan_eks(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_eks {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_eks = ComplianceRef {
        cis: "5.4",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let eks = aws_sdk_eks::Client::from_conf(
            aws_sdk_eks::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let clusters = match eks.list_clusters().send().await {
            Ok(c) => c.clusters().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for name in clusters {
            if count >= opts.max_resources_per_service {
                break;
            }
            count += 1;
            let node_id = format!("aws:eks:cluster:{name}");
            graph.upsert(&node_id, "eks_cluster", r, "internal", &[]);
            if let Ok(desc) = eks.describe_cluster().name(&name).send().await {
                if let Some(cluster) = desc.cluster() {
                    let public_api = cluster
                        .resources_vpc_config()
                        .map(|v| v.endpoint_public_access())
                        .unwrap_or(false);
                    if public_api {
                        graph.upsert(&node_id, "eks_cluster", r, "internet", &["public_api"]);
                        findings.push(posture_finding(
                            Domain::Compute,
                            "eks_public_api_endpoint",
                            &format!("EKS cluster public API endpoint: {name}"),
                            "high",
                            "T1190",
                            &c_eks,
                            target,
                            0.9,
                            &format!("EKS cluster '{name}' ({r}) has endpointPublicAccess=true — restrict to private + authorized CIDRs."),
                            "Disable public endpoint access or restrict publicAccessCidrs to known admin networks; use private endpoint + VPN/bastion.",
                            Evidence::new().with("cluster", name.clone()),
                            "eks_cluster",
                            &name,
                            r,
                        ));
                    }
                    let secrets_enc = cluster
                        .encryption_config()
                        .first()
                        .is_some();
                    if !secrets_enc {
                        findings.push(posture_finding(
                            Domain::Data,
                            "eks_secrets_not_encrypted",
                            &format!("EKS secrets envelope encryption disabled: {name}"),
                            "medium",
                            "T1552.004",
                            &c_eks,
                            target,
                            0.82,
                            &format!("EKS cluster '{name}' ({r}) has no encryptionConfig for Kubernetes secrets."),
                            "Enable envelope encryption for secrets using a KMS CMK.",
                            Evidence::new().with("cluster", name.clone()),
                            "eks_cluster",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── Internet-facing load balancers ────────────────────────────────────────────

async fn scan_elbv2(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_elb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_elb = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "4.1.1",
        nist: "PR.DS-2",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let elb = aws_sdk_elasticloadbalancingv2::Client::from_conf(
            aws_sdk_elasticloadbalancingv2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = elb.describe_load_balancers().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for lb in page.load_balancers() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("");
                if !scheme.eq_ignore_ascii_case("internet-facing") {
                    continue;
                }
                count += 1;
                let name = lb.load_balancer_name().unwrap_or("").to_string();
                let arn = lb.load_balancer_arn().unwrap_or("").to_string();
                let node_id = format!("aws:elbv2:{name}");
                graph.upsert(&node_id, "load_balancer", r, "internet", &["internet_facing"]);

                if let Ok(listeners) = elb.describe_listeners().load_balancer_arn(&arn).send().await {
                    for listener in listeners.listeners() {
                        let port = listener.port().unwrap_or(0);
                        let proto = listener.protocol().map(|p| p.as_str()).unwrap_or("");
                        if port == 80 && proto.eq_ignore_ascii_case("HTTP") {
                            findings.push(posture_finding(
                                Domain::Network,
                                "elb_http_cleartext_listener",
                                &format!("Internet-facing ALB cleartext HTTP listener: {name}"),
                                "medium",
                                "T1040",
                                &c_elb,
                                target,
                                0.86,
                                &format!("Load balancer '{name}' ({r}) exposes port 80/HTTP to the internet without TLS termination."),
                                "Redirect HTTP→HTTPS or terminate TLS on the ALB with a modern policy.",
                                Evidence::new().with("load_balancer", name.clone()).with("port", port),
                                "elbv2",
                                &name,
                                r,
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── Secrets Manager rotation ──────────────────────────────────────────────────

async fn scan_secrets_manager(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_secrets_manager {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sec = ComplianceRef {
        cis: "3.4",
        soc2: "CC6.1",
        iso27001: "A.9.4.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sm = aws_sdk_secretsmanager::Client::from_conf(
            aws_sdk_secretsmanager::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = sm.list_secrets().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for secret in page.secret_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = secret.name().unwrap_or("").to_string();
                let node_id = format!("aws:secretsmanager:{name}");
                graph.upsert(&node_id, "secret", r, "internal", &[]);
                if secret.rotation_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "secrets_manager_no_rotation",
                        &format!("Secret without automatic rotation: {name}"),
                        "medium",
                        "T1552.001",
                        &c_sec,
                        target,
                        0.8,
                        &format!("Secrets Manager secret '{name}' ({r}) has rotation disabled."),
                        "Enable automatic rotation with a Lambda rotator or migrate to dynamic secrets.",
                        Evidence::new().with("secret", name.clone()),
                        "secretsmanager_secret",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── SNS / SQS public messaging policies ───────────────────────────────────────

async fn scan_messaging(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_messaging {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_msg = ComplianceRef {
        cis: "2.1.5",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "1.3.1",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sns = aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut topic_count = 0usize;
        let mut tpag = sns.list_topics().into_paginator().send();
        while let Some(page) = tpag.next().await {
            let Ok(page) = page else { break };
            for topic in page.topics() {
                if topic_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                topic_count += 1;
                let arn = topic.topic_arn().unwrap_or("").to_string();
                if arn.is_empty() {
                    continue;
                }
                if let Ok(attrs) = sns.get_topic_attributes().topic_arn(&arn).send().await {
                    if let Some(policy) = attrs.attributes().and_then(|m| m.get("Policy"))
                    {
                        let lower = policy.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&format!("aws:sns:{arn}"), "sns_topic", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "sns_public_topic_policy",
                                "SNS topic allows wildcard principal",
                                "high",
                                "T1530",
                                &c_msg,
                                target,
                                0.88,
                                &format!("SNS topic {arn} ({r}) policy grants access to a wildcard principal."),
                                "Restrict SNS topic policy to specific account principals and source ARNs.",
                                Evidence::new().with("topic_arn", arn.clone()),
                                "sns_topic",
                                &arn,
                                r,
                            ));
                        }
                    }
                }
            }
        }

        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut q_count = 0usize;
        let mut qpag = sqs.list_queues().into_paginator().send();
        while let Some(page) = qpag.next().await {
            let Ok(page) = page else { break };
            for url in page.queue_urls() {
                if q_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                q_count += 1;
                if let Ok(attrs) = sqs
                    .get_queue_attributes()
                    .queue_url(url)
                    .attribute_names(aws_sdk_sqs::types::QueueAttributeName::Policy)
                    .send()
                    .await
                {
                    if let Some(policy) = attrs
                        .attributes()
                        .and_then(|m| m.get(&aws_sdk_sqs::types::QueueAttributeName::Policy))
                    {
                        let lower = policy.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&format!("aws:sqs:{url}"), "sqs_queue", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "sqs_public_queue_policy",
                                "SQS queue allows wildcard principal",
                                "high",
                                "T1530",
                                &c_msg,
                                target,
                                0.88,
                                &format!("SQS queue {url} ({r}) policy grants wildcard access."),
                                "Remove Principal \"*\" from the queue policy; use IAM conditions and VPC endpoints.",
                                Evidence::new().with("queue_url", url.clone()),
                                "sqs_queue",
                                url,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ECS Fargate/EC2 public task IPs ───────────────────────────────────────────

async fn scan_ecs(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_ecs {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ecs = ComplianceRef {
        cis: "5.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ecs = aws_sdk_ecs::Client::from_conf(
            aws_sdk_ecs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let clusters = match ecs.list_clusters().send().await {
            Ok(c) => c.cluster_arns().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for cluster_arn in clusters {
            if count >= opts.max_resources_per_service {
                break;
            }
            if let Ok(services) = ecs.list_services().cluster(&cluster_arn).send().await {
                for svc_arn in services.service_arns().iter().take(20) {
                    if count >= opts.max_resources_per_service {
                        break;
                    }
                    if let Ok(desc) = ecs.describe_services().cluster(&cluster_arn).services(svc_arn).send().await {
                        for svc in desc.services() {
                            count += 1;
                            let name = svc.service_name().unwrap_or("").to_string();
                            let public_ip = svc
                                .network_configuration()
                                .and_then(|n| n.awsvpc_configuration())
                                .map(|a| a.assign_public_ip() == Some(&aws_sdk_ecs::types::AssignPublicIp::Enabled))
                                .unwrap_or(false);
                            if public_ip {
                                let node_id = format!("aws:ecs:service:{name}");
                                graph.upsert(&node_id, "ecs_service", r, "internet", &["public_task_ip"]);
                                findings.push(posture_finding(
                                    Domain::Compute,
                                    "ecs_service_public_ip",
                                    &format!("ECS service assigns public IP: {name}"),
                                    "high",
                                    "T1190",
                                    &c_ecs,
                                    target,
                                    0.87,
                                    &format!("ECS service '{name}' in {r} has assignPublicIp=ENABLED on awsvpc tasks."),
                                    "Run tasks in private subnets with NAT gateway egress; remove public IP assignment.",
                                    Evidence::new().with("service", name.clone()).with("cluster", cluster_arn.clone()),
                                    "ecs_service",
                                    &name,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ElastiCache encryption at rest ────────────────────────────────────────────

async fn scan_elasticache(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_elasticache {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_cache = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec = aws_sdk_elasticache::Client::from_conf(
            aws_sdk_elasticache::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ec.describe_replication_groups().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for rg in page.replication_groups() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = rg.replication_group_id().unwrap_or("").to_string();
                let node_id = format!("aws:elasticache:{id}");
                graph.upsert(&node_id, "elasticache", r, "internal", &[]);
                if rg.at_rest_encryption_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Data,
                        "elasticache_no_encryption_at_rest",
                        &format!("ElastiCache replication group unencrypted at rest: {id}"),
                        "high",
                        "T1530",
                        &c_cache,
                        target,
                        0.86,
                        &format!("ElastiCache group '{id}' ({r}) does not have at-rest encryption enabled."),
                        "Create a new encrypted replication group and migrate; enable transit encryption.",
                        Evidence::new().with("replication_group", id.clone()),
                        "elasticache_replication_group",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── ECR container registry exposure ───────────────────────────────────────────

async fn scan_ecr(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_ecr {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_ecr = ComplianceRef {
        cis: "5.1",
        soc2: "CC6.6",
        iso27001: "A.8.2.3",
        pci: "6.5.3",
        nist: "PR.DS-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ecr = aws_sdk_ecr::Client::from_conf(
            aws_sdk_ecr::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ecr.describe_repositories().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for repo in page.repositories() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = repo.repository_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:ecr:repo:{name}");
                graph.upsert(&node_id, "ecr_repository", r, "internal", &[]);

                if let Ok(pol) = ecr.get_repository_policy().repository_name(&name).send().await {
                    if let Some(raw) = pol.policy_text() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                            || lower.contains("allusers")
                        {
                            graph.upsert(&node_id, "ecr_repository", r, "internet", &["public_pull"]);
                            findings.push(posture_finding(
                                Domain::Data,
                                "ecr_public_repository_policy",
                                &format!("ECR repository allows public pull: {name}"),
                                "critical",
                                "T1530",
                                &c_ecr,
                                target,
                                0.93,
                                &format!("ECR repo '{name}' ({r}) repository policy grants anonymous or wildcard pull — supply-chain poisoning risk."),
                                "Remove public pull; use private ECR with IAM-scoped ecr:BatchGetImage and image scanning on push.",
                                Evidence::new().with("repository", name.clone()),
                                "ecr_repository",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── ACM certificate expiry (TLS posture plane) ──────────────────────────────

async fn scan_acm(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_acm {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_acm = ComplianceRef {
        cis: "2.1.1",
        soc2: "CC6.6",
        iso27001: "A.10.1.2",
        pci: "4.1",
        nist: "PR.DS-2",
        gdpr: "Art.32",
    };
    let threshold_days = i64::try_from(opts.acm_expiry_days).unwrap_or(30);
    let now_secs = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(0);

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let acm = aws_sdk_acm::Client::from_conf(
            aws_sdk_acm::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = acm.list_certificates().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for summary in page.certificate_summary_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let arn = summary.certificate_arn().unwrap_or("").to_string();
                if arn.is_empty() {
                    continue;
                }
                let Ok(desc) = acm.describe_certificate().certificate_arn(&arn).send().await else {
                    continue;
                };
                let Some(cert) = desc.certificate() else { continue };
                let domain = cert.domain_name().unwrap_or("").to_string();
                let node_id = format!("aws:acm:{arn}");
                graph.upsert(&node_id, "acm_certificate", r, "internal", &[]);

                if let Some(not_after) = cert.not_after() {
                    let exp_secs = i64::try_from(not_after.secs()).unwrap_or(now_secs);
                    let days_left = (exp_secs - now_secs) / 86_400;
                    if days_left < 0 {
                        let days_expired = days_left.unsigned_abs();
                        graph.upsert(&node_id, "acm_certificate", r, "internet", &["expired_cert"]);
                        findings.push(posture_finding(
                            Domain::Network,
                            "acm_certificate_expired",
                            &format!("ACM certificate expired: {domain}"),
                            "critical",
                            "T1587",
                            &c_acm,
                            target,
                            0.96,
                            &format!("Certificate for '{domain}' ({r}) expired {days_expired} days ago — TLS interception or outage."),
                            "Renew or replace the certificate immediately; automate renewal via ACM DNS validation.",
                            Evidence::new().with("domain", domain.clone()).with("certificate_arn", arn.clone()),
                            "acm_certificate",
                            &domain,
                            r,
                        ));
                    } else if days_left <= threshold_days {
                        findings.push(posture_finding(
                            Domain::Network,
                            "acm_certificate_expiring",
                            &format!("ACM certificate expiring soon: {domain}"),
                            "high",
                            "T1587",
                            &c_acm,
                            target,
                            0.9,
                            &format!("Certificate for '{domain}' ({r}) expires in {days_left} days (threshold {threshold_days})."),
                            "Renew before expiry; enable ACM managed renewal with Route53 DNS validation.",
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("days_until_expiry", days_left)
                                .with("certificate_arn", arn),
                            "acm_certificate",
                            &domain,
                            r,
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ─── DynamoDB data-plane posture ───────────────────────────────────────────────

async fn scan_dynamodb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_dynamodb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    let c_pitr = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC7.2",
        iso27001: "A.12.3.1",
        pci: "10.2.1",
        nist: "PR.IP-4",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ddb = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = ddb.list_tables().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for table_name in page.table_names() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = table_name.to_string();
                let node_id = format!("aws:dynamodb:{name}");
                graph.upsert(&node_id, "dynamodb_table", r, "internal", &[]);

                let Ok(desc) = ddb.describe_table().table_name(&name).send().await else {
                    continue;
                };
                let Some(table) = desc.table() else { continue };

                let sse_on = table
                    .sse_description()
                    .and_then(|s| s.status())
                    .map(|s| s.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("ENABLED"));
                if !sse_on {
                    graph.upsert(&node_id, "dynamodb_table", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "dynamodb_no_encryption",
                        &format!("DynamoDB table without encryption at rest: {name}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Table '{name}' ({r}) does not have SSE enabled."),
                        "Enable encryption at rest with AWS-owned or CMK keys on all DynamoDB tables.",
                        Evidence::new().with("table", name.clone()),
                        "dynamodb_table",
                        &name,
                        r,
                    ));
                }

                if let Ok(pitr) = ddb
                    .describe_continuous_backups()
                    .table_name(&name)
                    .send()
                    .await
                {
                    let pitr_on = pitr
                        .continuous_backups_description()
                        .and_then(|c| c.point_in_time_recovery_description())
                        .and_then(|p| p.point_in_time_recovery_status())
                        .map(|s| s.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case("ENABLED"));
                    if !pitr_on {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "dynamodb_pitr_disabled",
                            &format!("DynamoDB PITR disabled: {name}"),
                            "medium",
                            "T1485",
                            &c_pitr,
                            target,
                            0.85,
                            &format!("Table '{name}' ({r}) has Point-in-Time Recovery disabled — no granular restore after ransomware/delete."),
                            "Enable PITR on all production DynamoDB tables.",
                            Evidence::new().with("table", name.clone()),
                            "dynamodb_table",
                            &name,
                            r,
                        ));
                    }
                }

                if let Some(arn) = table.table_arn() {
                    if let Ok(pol) = ddb.get_resource_policy().resource_arn(arn).send().await {
                        if let Some(raw) = pol.policy() {
                            let lower = raw.to_ascii_lowercase();
                            if lower.contains("\"principal\":\"*\"")
                                || lower.contains("\"aws\":\"*\"")
                            {
                                graph.upsert(&node_id, "dynamodb_table", r, "internet", &["public_resource_policy"]);
                                findings.push(posture_finding(
                                    Domain::Data,
                                    "dynamodb_public_resource_policy",
                                    &format!("DynamoDB table resource policy is public: {name}"),
                                    "critical",
                                    "T1530",
                                    &c_encrypt,
                                    target,
                                    0.94,
                                    &format!("Table '{name}' ({r}) resource policy grants wildcard access."),
                                    "Remove Principal \"*\"; scope to specific IAM roles and source VPC endpoints.",
                                    Evidence::new().with("table", name.clone()),
                                    "dynamodb_table",
                                    &name,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── API Gateway (REST + HTTP) exposure ────────────────────────────────────────

async fn scan_apigateway(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_apigateway {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_api = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }

        // REST APIs (v1) — public resource policy
        let apigw = aws_sdk_apigateway::Client::from_conf(
            aws_sdk_apigateway::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut rest_count = 0usize;
        let mut rpag = apigw.get_rest_apis().into_paginator().send();
        while let Some(page) = rpag.next().await {
            let Ok(page) = page else { break };
            for api in page.items() {
                if rest_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                rest_count += 1;
                let id = api.id().unwrap_or("").to_string();
                let name = api.name().unwrap_or("").to_string();
                let node_id = format!("aws:apigateway:rest:{id}");
                graph.upsert(&node_id, "apigateway_rest", r, "internal", &[]);

                if let Ok(api_detail) = apigw.get_rest_api().rest_api_id(&id).send().await {
                    if let Some(raw) = api_detail.policy() {
                        if !raw.is_empty() {
                            let lower = raw.to_ascii_lowercase();
                            if lower.contains("\"principal\":\"*\"")
                                || lower.contains("\"aws\":\"*\"")
                            {
                                graph.upsert(&node_id, "apigateway_rest", r, "internet", &["public_policy"]);
                                findings.push(posture_finding(
                                    Domain::Network,
                                    "apigateway_rest_public_policy",
                                    &format!("API Gateway REST API public policy: {name}"),
                                    "critical",
                                    "T1190",
                                    &c_api,
                                    target,
                                    0.93,
                                    &format!("REST API '{name}' ({id}, {r}) resource policy allows wildcard invoke."),
                                    "Remove public Principal; require IAM auth, Cognito, or Lambda authorizers.",
                                    Evidence::new().with("api_id", id.clone()).with("api_name", name.clone()),
                                    "apigateway_rest",
                                    &id,
                                    r,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // HTTP/WebSocket APIs (v2) — routes without authorization
        let apigwv2 = aws_sdk_apigatewayv2::Client::from_conf(
            aws_sdk_apigatewayv2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut v2_count = 0usize;
        if let Ok(apis_page) = apigwv2.get_apis().send().await {
            for api in apis_page.items() {
                if v2_count >= opts.max_resources_per_service / 2 {
                    break;
                }
                v2_count += 1;
                let id = api.api_id().unwrap_or("").to_string();
                let name = api.name().unwrap_or("").to_string();
                let endpoint = api.api_endpoint().unwrap_or("").to_string();
                let node_id = format!("aws:apigatewayv2:{id}");
                graph.upsert(&node_id, "apigateway_http", r, "internet", &[]);

                let mut open_routes = 0u32;
                if let Ok(routes_page) = apigwv2.get_routes().api_id(&id).send().await {
                    for route in routes_page.items() {
                        let auth = route
                            .authorization_type()
                            .map(|a| a.as_str())
                            .unwrap_or("NONE");
                        if auth.eq_ignore_ascii_case("NONE") {
                            open_routes += 1;
                        }
                    }
                }
                if open_routes > 0 {
                    graph.upsert(&node_id, "apigateway_http", r, "internet", &["open_routes"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "apigateway_http_no_auth_routes",
                        &format!("API Gateway HTTP API has unauthenticated routes: {name}"),
                        "high",
                        "T1190",
                        &c_api,
                        target,
                        0.9,
                        &format!(
                            "HTTP API '{name}' ({id}, {r}) exposes {open_routes} route(s) with AuthorizationType=NONE at {endpoint}."
                        ),
                        "Add JWT/Cognito/IAM authorizers; disable unused routes and the default execute-api endpoint if not needed.",
                        Evidence::new()
                            .with("api_id", id.clone())
                            .with("open_routes", open_routes)
                            .with("api_endpoint", endpoint),
                        "apigateway_http",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── OpenSearch / Elasticsearch domain exposure ──────────────────────────────

async fn scan_opensearch(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_opensearch {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_os = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let os = aws_sdk_opensearch::Client::from_conf(
            aws_sdk_opensearch::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let domains = match os.list_domain_names().send().await {
            Ok(d) => d.domain_names().to_vec(),
            Err(_) => continue,
        };
        let mut count = 0usize;
        for entry in domains {
            if count >= opts.max_resources_per_service {
                break;
            }
            count += 1;
            let name = entry.domain_name().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let Ok(desc) = os.describe_domain().domain_name(&name).send().await else {
                continue;
            };
            let Some(status) = desc.domain_status() else { continue };
            let node_id = format!("aws:opensearch:{name}");
            let in_vpc = status.vpc_options().is_some();
            let exposure = if in_vpc { "internal" } else { "internet" };
            graph.upsert(&node_id, "opensearch_domain", r, exposure, &[]);

            if !in_vpc {
                graph.upsert(&node_id, "opensearch_domain", r, "internet", &["public_endpoint"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "opensearch_public_domain",
                    &format!("OpenSearch domain without VPC isolation: {name}"),
                    "critical",
                    "T1530",
                    &c_os,
                    target,
                    0.94,
                    &format!("Domain '{name}' ({r}) is not deployed inside a VPC — endpoint is internet-reachable."),
                    "Redeploy into a VPC with restrictive security groups; use fine-grained access control.",
                    Evidence::new().with("domain", name.clone()),
                    "opensearch_domain",
                    &name,
                    r,
                ));
            }

            if status
                .encryption_at_rest_options()
                .and_then(|e| e.enabled())
                != Some(true)
            {
                findings.push(posture_finding(
                    Domain::Data,
                    "opensearch_no_encryption_at_rest",
                    &format!("OpenSearch domain without encryption at rest: {name}"),
                    "high",
                    "T1530",
                    &c_os,
                    target,
                    0.88,
                    &format!("Domain '{name}' ({r}) does not encrypt data at rest."),
                    "Enable encryption at rest with a CMK on all OpenSearch domains.",
                    Evidence::new().with("domain", name.clone()),
                    "opensearch_domain",
                    &name,
                    r,
                ));
            }

            if let Some(opts_ep) = status.domain_endpoint_options() {
                if opts_ep.enforce_https() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Network,
                        "opensearch_no_https_enforced",
                        &format!("OpenSearch domain allows cleartext HTTPS: {name}"),
                        "high",
                        "T1040",
                        &c_os,
                        target,
                        0.86,
                        &format!("Domain '{name}' ({r}) does not enforce HTTPS on the endpoint."),
                        "Set enforce_https=true and use a modern TLSSecurityPolicy.",
                        Evidence::new().with("domain", name.clone()),
                        "opensearch_domain",
                        &name,
                        r,
                    ));
                }
            }

            if let Some(pol) = status.access_policies() {
                let lower = pol.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                {
                    graph.upsert(&node_id, "opensearch_domain", r, "internet", &["public_access_policy"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "opensearch_public_access_policy",
                        &format!("OpenSearch domain access policy is public: {name}"),
                        "critical",
                        "T1530",
                        &c_os,
                        target,
                        0.95,
                        &format!("Domain '{name}' ({r}) access policy grants wildcard principals."),
                        "Replace with IP-based or IAM fine-grained policies; never use Principal \"*\".",
                        Evidence::new().with("domain", name.clone()),
                        "opensearch_domain",
                        &name,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── CloudFront edge delivery posture (global, us-east-1 API) ────────────────

fn s3_origin_missing_oac(origin: &aws_sdk_cloudfront::types::Origin) -> bool {
    let domain = origin.domain_name().to_ascii_lowercase();
    if !domain.contains(".s3.")
        && !domain.contains(".s3-website.")
        && !domain.contains(".s3.amazonaws.com")
    {
        return false;
    }
    let oac = origin
        .origin_access_control_id()
        .map(str::trim)
        .unwrap_or("");
    if !oac.is_empty() {
        return false;
    }
    let oai = origin
        .s3_origin_config()
        .map(|s| s.origin_access_identity().trim())
        .unwrap_or("");
    oai.is_empty()
}

async fn scan_cloudfront(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_cloudfront {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_edge = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let cf = aws_sdk_cloudfront::Client::from_conf(
        aws_sdk_cloudfront::config::Builder::from(sdk)
            .region(Region::new("us-east-1"))
            .build(),
    );
    let mut count = 0usize;
    let mut pag = cf.list_distributions().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        let Some(list) = page.distribution_list() else { continue };
        for dist in list.items() {
            if count >= opts.max_resources_per_service {
                break;
            }
            if !dist.enabled() {
                continue;
            }
            count += 1;
            let id = dist.id().to_string();
            let domain = dist.domain_name().to_string();
            let node_id = format!("aws:cloudfront:{id}");
            graph.upsert(&node_id, "cloudfront_distribution", "global", "internet", &[]);

            if let Some(origins) = dist.origins() {
                for origin in origins.items() {
                    let odom = origin.domain_name().to_string();
                    if !odom.is_empty() {
                        graph.link(&node_id, &format!("origin:{odom}"), "origin");
                    }
                    if s3_origin_missing_oac(origin) {
                        graph.upsert(
                            &node_id,
                            "cloudfront_distribution",
                            "global",
                            "internet",
                            &["s3_origin_no_oac"],
                        );
                        findings.push(posture_finding(
                            Domain::Data,
                            "cloudfront_s3_origin_no_oac",
                            &format!("CloudFront S3 origin without OAC/OAI: {domain}"),
                            "critical",
                            "T1530",
                            &c_edge,
                            target,
                            0.94,
                            &format!(
                                "Distribution '{domain}' ({id}) origin '{odom}' points at S3 without Origin Access Control — bucket may be directly reachable bypassing CloudFront auth."
                            ),
                            "Attach an Origin Access Control (OAC) and lock the S3 bucket policy to the distribution only.",
                            Evidence::new()
                                .with("distribution_id", id.clone())
                                .with("distribution_domain", domain.clone())
                                .with("origin_domain", odom),
                            "cloudfront_distribution",
                            &id,
                            "global",
                        ));
                    }
                }
            }

            if let Some(behavior) = dist.default_cache_behavior() {
                let vpp = behavior.viewer_protocol_policy().as_str();
                if vpp.eq_ignore_ascii_case("allow-all") {
                    graph.upsert(
                        &node_id,
                        "cloudfront_distribution",
                        "global",
                        "internet",
                        &["allows_http"],
                    );
                    findings.push(posture_finding(
                        Domain::Network,
                        "cloudfront_allows_http",
                        &format!("CloudFront distribution allows cleartext HTTP: {domain}"),
                        "high",
                        "T1040",
                        &c_edge,
                        target,
                        0.9,
                        &format!(
                            "Distribution '{domain}' ({id}) default cache behavior uses ViewerProtocolPolicy=allow-all — credentials and session tokens may traverse HTTP."
                        ),
                        "Set ViewerProtocolPolicy to redirect-to-https or https-only on all cache behaviors.",
                        Evidence::new()
                            .with("distribution_id", id.clone())
                            .with("viewer_protocol_policy", vpp),
                        "cloudfront_distribution",
                        &id,
                        "global",
                    ));
                }
            }

            let waf = dist.web_acl_id().trim();
            if waf.is_empty() {
                findings.push(posture_finding(
                    Domain::Network,
                    "cloudfront_no_waf",
                    &format!("CloudFront distribution without WAF: {domain}"),
                    "medium",
                    "T1190",
                    &c_edge,
                    target,
                    0.82,
                    &format!(
                        "Distribution '{domain}' ({id}) has no AWS WAF web ACL attached — edge lacks OWASP/bot/rate-limit protection."
                    ),
                    "Associate a WAFv2 web ACL (CloudFront scope) with logging to a dedicated CloudWatch log group.",
                    Evidence::new()
                        .with("distribution_id", id.clone())
                        .with("distribution_domain", domain.clone()),
                    "cloudfront_distribution",
                    &id,
                    "global",
                ));
            }
        }
    }

    findings
}

// ─── Route53 DNS governance (global) ─────────────────────────────────────────

async fn scan_route53(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_route53 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_dns = ComplianceRef {
        cis: "3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.DS-6",
        gdpr: "Art.32",
    };
    let r53 = aws_sdk_route53::Client::new(sdk);
    let mut public_zones: Vec<(String, String)> = Vec::new();
    let mut pag = r53.list_hosted_zones().into_paginator().send();
    while let Some(page) = pag.next().await {
        let Ok(page) = page else { break };
        for zone in page.hosted_zones() {
            if public_zones.len() >= opts.max_resources_per_service {
                break;
            }
            let private = zone.config().map(|c| c.private_zone()).unwrap_or(false);
            if private {
                continue;
            }
            let id = zone.id().to_string();
            let name = zone.name().trim_end_matches('.').to_string();
            let node_id = format!("aws:route53:{id}");
            graph.upsert(&node_id, "route53_public_zone", "global", "internet", &[]);
            public_zones.push((id.clone(), name.clone()));

            if let Ok(dnssec) = r53.get_dnssec().hosted_zone_id(&id).send().await {
                let signing = dnssec.key_signing_keys().iter().any(|k| {
                    k.status()
                        .is_some_and(|s| s.eq_ignore_ascii_case("ACTIVE"))
                });
                if !signing {
                    findings.push(posture_finding(
                        Domain::Network,
                        "route53_dnssec_disabled",
                        &format!("Public Route53 zone without DNSSEC: {name}"),
                        "high",
                        "T1557",
                        &c_dns,
                        target,
                        0.88,
                        &format!(
                            "Public hosted zone '{name}' ({id}) has no active DNSSEC key signing keys — vulnerable to DNS hijacking/cache poisoning at resolvers."
                        ),
                        "Enable DNSSEC signing on the hosted zone and establish DS records at the registrar.",
                        Evidence::new().with("zone_id", id).with("zone_name", name.clone()),
                        "route53_zone",
                        &name,
                        "global",
                    ));
                }
            }
        }
    }

    if !public_zones.is_empty() {
        let mut logged_zones = BTreeSet::new();
        let mut qpag = r53.list_query_logging_configs().into_paginator().send();
        while let Some(page) = qpag.next().await {
            let Ok(page) = page else { break };
            for cfg in page.query_logging_configs() {
                logged_zones.insert(cfg.hosted_zone_id().to_string());
            }
        }
        for (id, name) in public_zones {
            let short_id = id.trim_start_matches("/hostedzone/");
            if logged_zones.contains(short_id) {
                continue;
            }
            findings.push(posture_finding(
                Domain::Governance,
                "route53_query_logging_disabled",
                &format!("Route53 query logging disabled: {name}"),
                "medium",
                "T1562.002",
                &c_dns,
                target,
                0.8,
                &format!(
                    "Public hosted zone '{name}' ({id}) has no Route53 Resolver query logging — DNS exfiltration and tunneling may go undetected."
                ),
                "Create a query logging configuration shipping to a dedicated, encrypted CloudWatch log group with alerting.",
                Evidence::new()
                    .with("zone_id", id.clone())
                    .with("zone_name", name.clone()),
                "route53_zone",
                &name,
                "global",
            ));
        }
    }

    findings
}

// ─── EventBridge event bus policy posture (regional) ─────────────────────────

async fn scan_eventbridge(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_eventbridge {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_bus = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let eb = aws_sdk_eventbridge::Client::from_conf(
            aws_sdk_eventbridge::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let buses = match eb.list_event_buses().send().await {
            Ok(b) => b.event_buses().to_vec(),
            Err(_) => continue,
        };
        let mut bus_count = 0usize;
        for bus in buses {
            if bus_count >= opts.max_resources_per_service / 4 {
                break;
            }
            bus_count += 1;
            let name = bus.name().unwrap_or("default").to_string();
            let arn = bus.arn().unwrap_or("").to_string();
            let node_id = format!("aws:eventbridge:{r}:{name}");
            graph.upsert(&node_id, "eventbridge_bus", r, "internal", &[]);

            let Ok(desc) = eb.describe_event_bus().name(&name).send().await else {
                continue;
            };
            if let Some(raw) = desc.policy() {
                let lower = raw.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                    || lower.contains("\"principal\":{\"aws\":\"*\"}")
                {
                    graph.upsert(&node_id, "eventbridge_bus", r, "internet", &["public_policy"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "eventbridge_public_bus_policy",
                        &format!("EventBridge bus allows wildcard principal: {name}"),
                        "critical",
                        "T1190",
                        &c_bus,
                        target,
                        0.93,
                        &format!(
                            "Event bus '{name}' ({r}) resource policy grants wildcard PutEvents/Invoke access — cross-account event injection risk."
                        ),
                        "Remove Principal \"*\"; scope to specific account IDs and use aws:SourceArn conditions.",
                        Evidence::new().with("event_bus", name.clone()).with("event_bus_arn", arn),
                        "eventbridge_bus",
                        &name,
                        r,
                    ));
                }
            }

            // Rules forwarding to Lambda — link graph for toxic-path correlation
            if let Ok(rules_page) = eb.list_rules().event_bus_name(&name).send().await {
                for rule in rules_page.rules().iter().take(50) {
                    let rule_name = rule.name().unwrap_or("").to_string();
                    if rule_name.is_empty() {
                        continue;
                    }
                    if let Ok(targets) = eb
                        .list_targets_by_rule()
                        .rule(&rule_name)
                        .event_bus_name(&name)
                        .send()
                        .await
                    {
                        for t in targets.targets() {
                            let lambda_arn = t.arn();
                            if lambda_arn.contains(":lambda:") {
                                graph.link(&node_id, lambda_arn, "targets_lambda");
                                graph.upsert(lambda_arn, "lambda_function", r, "internal", &[]);
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

// ─── WAFv2 edge + regional protection posture ──────────────────────────────────

async fn scan_wafv2_acl_scope(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
    scope: aws_sdk_wafv2::types::Scope,
    region: &str,
    count: &mut usize,
) -> Vec<Value> {
    let mut findings = Vec::new();
    if *count >= opts.max_resources_per_service {
        return findings;
    }
    let c_waf = ComplianceRef {
        cis: "4.3",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let reg = if scope == aws_sdk_wafv2::types::Scope::Cloudfront {
        "us-east-1".to_string()
    } else {
        region.to_string()
    };
    let waf = aws_sdk_wafv2::Client::from_conf(
        aws_sdk_wafv2::config::Builder::from(sdk)
            .region(Region::new(reg.clone()))
            .build(),
    );
    let scope_label = if scope == aws_sdk_wafv2::types::Scope::Cloudfront {
        "cloudfront"
    } else {
        "regional"
    };
    let mut marker: Option<String> = None;
    loop {
        if *count >= opts.max_resources_per_service {
            break;
        }
        let mut req = waf.list_web_acls().scope(scope.clone());
        if let Some(m) = &marker {
            req = req.next_marker(m);
        }
        let Ok(page) = req.send().await else { break };
        for acl in page.web_acls() {
            if *count >= opts.max_resources_per_service {
                break;
            }
            *count += 1;
            let name = acl.name().unwrap_or("").to_string();
            let id = acl.id().unwrap_or("").to_string();
            let arn = acl.arn().unwrap_or("").to_string();
            if name.is_empty() || arn.is_empty() {
                continue;
            }
            let node_id = format!("aws:wafv2:{scope_label}:{name}");
            graph.upsert(&node_id, "wafv2_web_acl", &reg, "internal", &[]);

            let has_logging = waf
                .get_logging_configuration()
                .resource_arn(&arn)
                .send()
                .await
                .is_ok();
            if !has_logging {
                findings.push(posture_finding(
                    Domain::Governance,
                    "wafv2_no_logging",
                    &format!("WAFv2 web ACL without logging ({scope_label}): {name}"),
                    "medium",
                    "T1562.002",
                    &c_waf,
                    target,
                    0.84,
                    &format!(
                        "Web ACL '{name}' ({scope_label}, {reg}) has no logging configuration — blocked attacks leave no forensic trail."
                    ),
                    "Enable WAF logging to S3, CloudWatch Logs, or Firehose with at least 90-day retention.",
                    Evidence::new()
                        .with("web_acl", name.clone())
                        .with("scope", scope_label)
                        .with("arn", arn.clone()),
                    "wafv2_web_acl",
                    &name,
                    &reg,
                ));
            }

            if let Ok(detail) = waf
                .get_web_acl()
                .name(&name)
                .id(&id)
                .scope(scope.clone())
                .send()
                .await
            {
                let rule_count = detail
                    .web_acl()
                    .map(|w| w.rules().len())
                    .unwrap_or(0);
                if rule_count == 0 {
                    graph.upsert(&node_id, "wafv2_web_acl", &reg, "internet", &["no_rules"]);
                    findings.push(posture_finding(
                        Domain::Network,
                        "wafv2_no_rules",
                        &format!("WAFv2 web ACL has zero rules ({scope_label}): {name}"),
                        "high",
                        "T1190",
                        &c_waf,
                        target,
                        0.9,
                        &format!(
                            "Web ACL '{name}' ({scope_label}, {reg}) defines no rules — attached resources get pass-through protection only."
                        ),
                        "Add AWSManagedRules or custom rules; never rely on default Allow action alone.",
                        Evidence::new()
                            .with("web_acl", name)
                            .with("scope", scope_label)
                            .with("rule_count", rule_count),
                        "wafv2_web_acl",
                        &id,
                        &reg,
                    ));
                }
            }
        }
        marker = page.next_marker().map(str::to_string);
        if marker.is_none() {
            break;
        }
    }
    findings
}

async fn scan_wafv2(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_wafv2 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut count = 0usize;
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        findings.extend(
            scan_wafv2_acl_scope(
                sdk,
                opts,
                target,
                graph,
                aws_sdk_wafv2::types::Scope::Regional,
                r,
                &mut count,
            )
            .await,
        );
    }
    findings.extend(
        scan_wafv2_acl_scope(
            sdk,
            opts,
            target,
            graph,
            aws_sdk_wafv2::types::Scope::Cloudfront,
            "global",
            &mut count,
        )
        .await,
    );
    findings
}

// ─── CloudWatch Logs retention & resource-policy posture ───────────────────────

async fn scan_cloudwatch_logs(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_cloudwatch_logs {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_logs = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "PR.PT-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let logs = aws_sdk_cloudwatchlogs::Client::from_conf(
            aws_sdk_cloudwatchlogs::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut lg_count = 0usize;
        let mut pag = logs.describe_log_groups().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for lg in page.log_groups() {
                if lg_count >= opts.max_resources_per_service {
                    break;
                }
                lg_count += 1;
                let name = lg.log_group_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:logs:{name}");
                graph.upsert(&node_id, "cloudwatch_log_group", r, "internal", &[]);

                if lg.retention_in_days().is_none() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "logs_no_retention",
                        &format!("CloudWatch log group without retention: {name}"),
                        "medium",
                        "T1562.002",
                        &c_logs,
                        target,
                        0.82,
                        &format!(
                            "Log group '{name}' ({r}) has no retention policy — logs persist indefinitely, increasing breach blast radius and cost."
                        ),
                        "Set retention (30–365 days) on all log groups; ship security logs to a centralized immutable store.",
                        Evidence::new().with("log_group", name.clone()),
                        "cloudwatch_log_group",
                        &name,
                        r,
                    ));
                }
            }
        }

        if let Ok(pols) = logs.describe_resource_policies().send().await {
            for pol in pols.resource_policies() {
                let Some(raw) = pol.policy_document() else { continue };
                let lower = raw.to_ascii_lowercase();
                if lower.contains("\"principal\":\"*\"")
                    || lower.contains("\"aws\":\"*\"")
                    || lower.contains("\"principal\":{\"aws\":\"*\"}")
                {
                    let pname = pol.policy_name().unwrap_or("").to_string();
                    graph.upsert(
                        &format!("aws:logs:policy:{pname}"),
                        "cloudwatch_resource_policy",
                        r,
                        "internet",
                        &["public_policy"],
                    );
                    findings.push(posture_finding(
                        Domain::Governance,
                        "logs_public_resource_policy",
                        &format!("CloudWatch Logs resource policy allows wildcard: {pname}"),
                        "high",
                        "T1530",
                        &c_logs,
                        target,
                        0.88,
                        &format!(
                            "Account/region {r} CloudWatch Logs resource policy '{pname}' grants wildcard principals — cross-account log injection or exfiltration."
                        ),
                        "Remove Principal \"*\"; scope log group access to specific roles and source accounts.",
                        Evidence::new().with("policy_name", pname.clone()),
                        "cloudwatch_resource_policy",
                        &pname,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Redshift data warehouse exposure ────────────────────────────────────────

async fn scan_redshift(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_redshift {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let rs = aws_sdk_redshift::Client::from_conf(
            aws_sdk_redshift::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = rs.describe_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:redshift:{id}");
                let exposure = if cluster.publicly_accessible() == Some(true) {
                    "internet"
                } else {
                    "internal"
                };
                graph.upsert(&node_id, "redshift_cluster", r, exposure, &[]);

                if cluster.publicly_accessible() == Some(true) {
                    graph.upsert(&node_id, "redshift_cluster", r, "internet", &["public_warehouse"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "redshift_publicly_accessible",
                        &format!("Redshift cluster publicly accessible: {id}"),
                        "critical",
                        "T1190",
                        &c_public,
                        target,
                        0.95,
                        &format!(
                            "Redshift cluster '{id}' ({r}) has publicly_accessible=true — analytics warehouse reachable from the internet."
                        ),
                        "Disable public access; use VPC endpoints, PrivateLink, or VPN-only connectivity.",
                        Evidence::new()
                            .with("cluster", id.clone())
                            .with("endpoint", cluster.endpoint().and_then(|e| e.address()).unwrap_or("")),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.encrypted() == Some(false) {
                    graph.upsert(&node_id, "redshift_cluster", r, exposure, &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "redshift_unencrypted",
                        &format!("Redshift cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Redshift cluster '{id}' ({r}) is not encrypted at rest."),
                        "Enable encryption at rest with a CMK; migrate to an encrypted cluster.",
                        Evidence::new().with("cluster", id.clone()),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }

                let audit_on = rs
                    .describe_logging_status()
                    .cluster_identifier(&id)
                    .send()
                    .await
                    .ok()
                    .and_then(|l| l.logging_enabled())
                    .unwrap_or(false);
                if !audit_on {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "redshift_audit_logging_disabled",
                        &format!("Redshift audit logging disabled: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.83,
                        &format!(
                            "Redshift cluster '{id}' ({r}) does not ship audit logs to S3/CloudWatch — SQL exfiltration may go undetected."
                        ),
                        "Enable Redshift audit logging to a dedicated, encrypted, retention-bounded log destination.",
                        Evidence::new().with("cluster", id.clone()),
                        "redshift_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }
    }

    findings
}

// ─── Amazon DocumentDB (Mongo-compatible) posture ────────────────────────────

async fn scan_documentdb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_documentdb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };

    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let docdb = aws_sdk_docdb::Client::from_conf(
            aws_sdk_docdb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = docdb.describe_db_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.db_clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.db_cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:documentdb:{id}");
                graph.upsert(&node_id, "documentdb_cluster", r, "internal", &[]);

                if cluster.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "documentdb_cluster", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "documentdb_unencrypted",
                        &format!("DocumentDB cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.89,
                        &format!("DocumentDB cluster '{id}' ({r}) does not encrypt storage at rest."),
                        "Enable storage encryption with a CMK on all DocumentDB clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.backup_retention_period() == Some(0) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_backups",
                        &format!("DocumentDB cluster without backups: {id}"),
                        "medium",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.8,
                        &format!(
                            "DocumentDB cluster '{id}' ({r}) has backup_retention_period=0 — no point-in-time recovery after ransomware."
                        ),
                        "Set backup retention ≥ 7 days; test restore procedures regularly.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster
                    .enabled_cloudwatch_logs_exports()
                    .is_empty()
                {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_audit_logs",
                        &format!("DocumentDB cluster without CloudWatch audit logs: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.81,
                        &format!(
                            "DocumentDB cluster '{id}' ({r}) exports no CloudWatch log types — audit/Profiler logs disabled."
                        ),
                        "Enable audit and profiler log exports to CloudWatch Logs with retention and alerting.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.deletion_protection() == Some(false) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "documentdb_no_deletion_protection",
                        &format!("DocumentDB cluster without deletion protection: {id}"),
                        "low",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.75,
                        &format!("DocumentDB cluster '{id}' ({r}) can be deleted in a single API call — ransomware/insider risk."),
                        "Enable deletion_protection on production DocumentDB clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "documentdb_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }

        let mut inst_count = 0usize;
        let mut ipag = docdb.describe_db_instances().into_paginator().send();
        while let Some(page) = ipag.next().await {
            let Ok(page) = page else { break };
            for inst in page.db_instances() {
                if inst_count >= opts.max_resources_per_service {
                    break;
                }
                inst_count += 1;
                if inst.publicly_accessible() != Some(true) {
                    continue;
                }
                let id = inst.db_instance_identifier().unwrap_or("").to_string();
                let cluster_id = inst.db_cluster_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:documentdb:instance:{id}");
                graph.upsert(&node_id, "documentdb_instance", r, "internet", &["public_docdb"]);
                findings.push(posture_finding(
                    Domain::Data,
                    "documentdb_publicly_accessible",
                    &format!("DocumentDB instance publicly accessible: {id}"),
                    "critical",
                    "T1190",
                    &c_public,
                    target,
                    0.94,
                    &format!(
                        "DocumentDB instance '{id}' (cluster '{cluster_id}', {r}) has publicly_accessible=true."
                    ),
                    "Set publicly_accessible=false; restrict to private subnets and security groups.",
                    Evidence::new()
                        .with("instance", id.clone())
                        .with("cluster", cluster_id),
                    "documentdb_instance",
                    &id,
                    r,
                ));
            }
        }
    }

    findings
}

// ─── Neptune graph database posture ────────────────────────────────────────────

async fn scan_neptune(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_neptune {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_public = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.6",
        iso27001: "A.13.1.1",
        pci: "1.3.1",
        nist: "PR.AC-5",
        gdpr: "Art.32",
    };
    let c_encrypt = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let nep = aws_sdk_neptune::Client::from_conf(
            aws_sdk_neptune::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = nep.describe_db_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.db_clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let id = cluster.db_cluster_identifier().unwrap_or("").to_string();
                if id.is_empty() {
                    continue;
                }
                let node_id = format!("aws:neptune:{id}");
                graph.upsert(&node_id, "neptune_cluster", r, "internal", &[]);

                if cluster.storage_encrypted() == Some(false) {
                    graph.upsert(&node_id, "neptune_cluster", r, "internal", &["unencrypted"]);
                    findings.push(posture_finding(
                        Domain::Data,
                        "neptune_unencrypted",
                        &format!("Neptune cluster without encryption: {id}"),
                        "high",
                        "T1530",
                        &c_encrypt,
                        target,
                        0.9,
                        &format!("Neptune cluster '{id}' ({r}) does not encrypt storage at rest."),
                        "Enable storage encryption with a CMK on all Neptune clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.backup_retention_period() == Some(0) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_backups",
                        &format!("Neptune cluster without backups: {id}"),
                        "medium",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.81,
                        &format!(
                            "Neptune cluster '{id}' ({r}) has backup_retention_period=0 — no point-in-time recovery after ransomware."
                        ),
                        "Set backup retention ≥ 7 days; test restore procedures regularly.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.enabled_cloudwatch_logs_exports().is_empty() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_audit_logs",
                        &format!("Neptune cluster without CloudWatch audit logs: {id}"),
                        "medium",
                        "T1562.002",
                        &c_encrypt,
                        target,
                        0.82,
                        &format!(
                            "Neptune cluster '{id}' ({r}) exports no CloudWatch log types — Gremlin/audit logs disabled."
                        ),
                        "Enable audit and slow-query log exports to CloudWatch Logs with retention and alerting.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.deletion_protection() == Some(false) {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "neptune_no_deletion_protection",
                        &format!("Neptune cluster without deletion protection: {id}"),
                        "low",
                        "T1485",
                        &c_encrypt,
                        target,
                        0.76,
                        &format!("Neptune cluster '{id}' ({r}) can be deleted in a single API call — ransomware/insider risk."),
                        "Enable deletion_protection on production Neptune clusters.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }

                if cluster.iam_database_authentication_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Identity,
                        "neptune_no_iam_auth",
                        &format!("Neptune cluster without IAM DB authentication: {id}"),
                        "medium",
                        "T1078.004",
                        &c_encrypt,
                        target,
                        0.78,
                        &format!(
                            "Neptune cluster '{id}' ({r}) does not enforce IAM database authentication — static credentials may persist."
                        ),
                        "Enable IAM DB authentication and rotate away from static master passwords.",
                        Evidence::new().with("cluster", id.clone()),
                        "neptune_cluster",
                        &id,
                        r,
                    ));
                }
            }
        }

        let mut inst_count = 0usize;
        let mut ipag = nep.describe_db_instances().into_paginator().send();
        while let Some(page) = ipag.next().await {
            let Ok(page) = page else { break };
            for inst in page.db_instances() {
                if inst_count >= opts.max_resources_per_service {
                    break;
                }
                inst_count += 1;
                if inst.publicly_accessible() != Some(true) {
                    continue;
                }
                let id = inst.db_instance_identifier().unwrap_or("").to_string();
                let cluster_id = inst.db_cluster_identifier().unwrap_or("").to_string();
                let node_id = format!("aws:neptune:instance:{id}");
                graph.upsert(&node_id, "neptune_instance", r, "internet", &["public_graph"]);
                graph.upsert(
                    &format!("aws:neptune:{cluster_id}"),
                    "neptune_cluster",
                    r,
                    "internet",
                    &["public_graph"],
                );
                findings.push(posture_finding(
                    Domain::Data,
                    "neptune_publicly_accessible",
                    &format!("Neptune instance publicly accessible: {id}"),
                    "critical",
                    "T1190",
                    &c_public,
                    target,
                    0.95,
                    &format!(
                        "Neptune instance '{id}' (cluster '{cluster_id}', {r}) has publicly_accessible=true — graph DB reachable from the internet."
                    ),
                    "Set publicly_accessible=false; use private subnets and security groups only.",
                    Evidence::new()
                        .with("instance", id.clone())
                        .with("cluster", cluster_id),
                    "neptune_instance",
                    &id,
                    r,
                ));
            }
        }
    }
    findings
}

// ─── MemoryDB (Redis-compatible) posture ───────────────────────────────────────

async fn scan_memorydb(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_memorydb {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_data = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.10.1.1",
        pci: "3.4.1",
        nist: "PR.DS-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let mdb = aws_sdk_memorydb::Client::from_conf(
            aws_sdk_memorydb::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = mdb.describe_clusters().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for cluster in page.clusters() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = cluster.name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:memorydb:{name}");
                graph.upsert(&node_id, "memorydb_cluster", r, "internal", &[]);
                if cluster.tls_enabled() != Some(true) {
                    findings.push(posture_finding(
                        Domain::Data,
                        "memorydb_tls_disabled",
                        &format!("MemoryDB cluster without TLS in transit: {name}"),
                        "high",
                        "T1040",
                        &c_data,
                        target,
                        0.88,
                        &format!("MemoryDB cluster '{name}' ({r}) does not enforce TLS in transit."),
                        "Enable in-transit encryption (TLS) on all MemoryDB clusters.",
                        Evidence::new().with("cluster", name.clone()),
                        "memorydb_cluster",
                        &name,
                        r,
                    ));
                }
                if let Some(acl) = cluster.acl_name() {
                    if acl.eq_ignore_ascii_case("open-access") {
                            graph.upsert(&node_id, "memorydb_cluster", r, "internet", &["open_acl"]);
                            findings.push(posture_finding(
                                Domain::Network,
                                "memorydb_open_acl",
                                &format!("MemoryDB cluster uses open-access ACL: {name}"),
                                "critical",
                                "T1190",
                                &c_data,
                                target,
                                0.93,
                                &format!("MemoryDB cluster '{name}' ({r}) uses the open-access ACL — reachable beyond intended principals."),
                                "Replace open-access ACL with a restrictive custom ACL scoped to application security groups.",
                                Evidence::new().with("cluster", name.clone()).with("acl", acl),
                                "memorydb_cluster",
                                &name,
                                r,
                            ));
                    }
                }
            }
        }
    }
    findings
}

// ─── AWS Backup vault posture ──────────────────────────────────────────────────

async fn scan_backup(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_backup {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_backup = ComplianceRef {
        cis: "2.3.1",
        soc2: "CC6.1",
        iso27001: "A.12.3.1",
        pci: "3.4.1",
        nist: "PR.IP-4",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let backup = aws_sdk_backup::Client::from_conf(
            aws_sdk_backup::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = backup.list_backup_vaults().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for vault in page.backup_vault_list() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = vault.backup_vault_name().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let node_id = format!("aws:backup:vault:{name}");
                graph.upsert(&node_id, "backup_vault", r, "internal", &[]);
                if vault.encryption_key_arn().is_none() {
                    findings.push(posture_finding(
                        Domain::Governance,
                        "backup_vault_no_cmk",
                        &format!("AWS Backup vault without CMK encryption: {name}"),
                        "medium",
                        "T1530",
                        &c_backup,
                        target,
                        0.83,
                        &format!("Backup vault '{name}' ({r}) uses default encryption — no customer-managed key for backup isolation."),
                        "Configure a dedicated KMS CMK for the backup vault with least-privilege key policies.",
                        Evidence::new().with("vault", name.clone()),
                        "backup_vault",
                        &name,
                        r,
                    ));
                }
                if let Ok(pol) = backup.get_backup_vault_access_policy().backup_vault_name(&name).send().await {
                    if let Some(raw) = pol.policy() {
                        let lower = raw.to_ascii_lowercase();
                        if lower.contains("\"principal\":\"*\"")
                            || lower.contains("\"aws\":\"*\"")
                        {
                            graph.upsert(&node_id, "backup_vault", r, "internet", &["public_policy"]);
                            findings.push(posture_finding(
                                Domain::Governance,
                                "backup_vault_public_policy",
                                &format!("AWS Backup vault allows wildcard principal: {name}"),
                                "critical",
                                "T1530",
                                &c_backup,
                                target,
                                0.94,
                                &format!("Backup vault '{name}' ({r}) access policy grants wildcard access — cross-account backup exfiltration."),
                                "Remove Principal \"*\"; scope backup vault access to specific accounts and roles.",
                                Evidence::new().with("vault", name.clone()),
                                "backup_vault",
                                &name,
                                r,
                            ));
                        }
                    }
                }
            }
        }
    }
    findings
}

// ─── AWS Organizations / SCP governance ────────────────────────────────────────

async fn scan_organizations(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_organizations {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_org = ComplianceRef {
        cis: "1.1",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "7.1.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let org = aws_sdk_organizations::Client::new(sdk);
    let Ok(desc) = org.describe_organization().send().await else {
        return findings;
    };
    let org_id = desc
        .organization()
        .and_then(|o| o.id())
        .unwrap_or("")
        .to_string();
    if org_id.is_empty() {
        return findings;
    }
    graph.upsert(
        &format!("aws:organizations:{org_id}"),
        "aws_organization",
        "global",
        "internal",
        &[],
    );
    let roots = match org.list_roots().send().await {
        Ok(r) => r.roots().to_vec(),
        Err(_) => return findings,
    };
    for root in roots {
        let root_id = root.id().unwrap_or("").to_string();
        if root_id.is_empty() {
            continue;
        }
        let attached = match org
            .list_policies_for_target()
            .target_id(&root_id)
            .filter(aws_sdk_organizations::types::PolicyType::ServiceControlPolicy)
            .send()
            .await
        {
            Ok(a) => a.policies().to_vec(),
            Err(_) => continue,
        };
        for pol in attached {
            let pid = pol.id().unwrap_or("").to_string();
            let pname = pol.name().unwrap_or("").to_string();
            if pname.eq_ignore_ascii_case("FullAWSAccess") {
                findings.push(posture_finding(
                    Domain::Governance,
                    "organizations_full_aws_access_scp",
                    &format!("Organization root has FullAWSAccess SCP attached: {pname}"),
                    "high",
                    "T1078.004",
                    &c_org,
                    target,
                    0.87,
                    &format!(
                        "Root target in org {org_id} has the default FullAWSAccess SCP — no org-wide guardrail beyond account boundaries."
                    ),
                    "Attach restrictive SCPs at the root/OU level; use FullAWSAccess only as baseline and layer deny SCPs for sensitive services.",
                    Evidence::new().with("policy_id", pid.clone()).with("policy_name", pname.clone()),
                    "organizations_scp",
                    &pname,
                    "global",
                ));
            }
            if let Ok(doc) = org.describe_policy().policy_id(&pid).send().await {
                if let Some(content) = doc.policy().and_then(|p| p.content()) {
                    let lower = content.to_ascii_lowercase();
                    if lower.contains("\"effect\":\"allow\"")
                        && lower.contains("\"action\":\"*\"")
                        && lower.contains("\"resource\":\"*\"")
                        && !pname.eq_ignore_ascii_case("FullAWSAccess")
                    {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "organizations_permissive_scp",
                            &format!("Organization SCP allows wildcard actions: {pname}"),
                            "medium",
                            "T1078.004",
                            &c_org,
                            target,
                            0.8,
                            &format!("SCP '{pname}' attached to root {root_id} contains Allow * on * — weak org guardrail."),
                            "Replace wildcard Allow SCPs with explicit service/action allow-lists and deny SCPs for sensitive APIs.",
                            Evidence::new().with("policy_id", pid).with("policy_name", pname.clone()),
                            "organizations_scp",
                            &pname,
                            "global",
                        ));
                    }
                }
            }
        }
    }
    findings
}

// ─── Step Functions audit posture ──────────────────────────────────────────────

async fn scan_sfn(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_sfn {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sfn = ComplianceRef {
        cis: "3.1",
        soc2: "CC7.2",
        iso27001: "A.12.4.1",
        pci: "10.2.1",
        nist: "PR.PT-1",
        gdpr: "Art.32",
    };
    for reg in opts.effective_regions() {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let sfn = aws_sdk_sfn::Client::from_conf(
            aws_sdk_sfn::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );
        let mut count = 0usize;
        let mut pag = sfn.list_state_machines().into_paginator().send();
        while let Some(page) = pag.next().await {
            let Ok(page) = page else { break };
            for sm in page.state_machines() {
                if count >= opts.max_resources_per_service {
                    break;
                }
                count += 1;
                let name = sm.name().to_string();
                let arn = sm.state_machine_arn().to_string();
                if name.is_empty() || arn.is_empty() {
                    continue;
                }
                let node_id = format!("aws:sfn:{name}");
                graph.upsert(&node_id, "sfn_state_machine", r, "internal", &[]);
                if let Ok(detail) = sfn.describe_state_machine().state_machine_arn(&arn).send().await {
                    let logging = detail
                        .logging_configuration()
                        .and_then(|l| l.level())
                        .map(|l| l.as_str())
                        .unwrap_or("OFF");
                    if logging.eq_ignore_ascii_case("OFF") {
                        findings.push(posture_finding(
                            Domain::Governance,
                            "sfn_logging_disabled",
                            &format!("Step Functions state machine logging disabled: {name}"),
                            "medium",
                            "T1562.002",
                            &c_sfn,
                            target,
                            0.82,
                            &format!("State machine '{name}' ({r}) has CloudWatch logging level OFF — workflow abuse is invisible."),
                            "Enable logging at ERROR or ALL level to CloudWatch Logs with retention and alerting.",
                            Evidence::new().with("state_machine", name.clone()).with("arn", arn),
                            "sfn_state_machine",
                            &name,
                            r,
                        ));
                    }
                }
            }
        }
    }
    findings
}

// ─── IAM Identity Center (SSO) posture ───────────────────────────────────────

async fn scan_sso(
    sdk: &SdkConfig,
    opts: &CloudScanOptions,
    target: &str,
    graph: &mut SecurityGraph,
) -> Vec<Value> {
    if !opts.check_sso {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let c_sso = ComplianceRef {
        cis: "1.1",
        soc2: "CC6.1",
        iso27001: "A.9.2.1",
        pci: "8.2.1",
        nist: "PR.AC-1",
        gdpr: "Art.32",
    };
    let sso = aws_sdk_ssoadmin::Client::from_conf(
        aws_sdk_ssoadmin::config::Builder::from(sdk)
            .region(Region::new("us-east-1"))
            .build(),
    );
    let instances = match sso.list_instances().send().await {
        Ok(i) => i.instances().to_vec(),
        Err(_) => return findings,
    };
    if instances.is_empty() {
        findings.push(posture_finding(
            Domain::Identity,
            "sso_not_configured",
            "IAM Identity Center (SSO) not enabled",
            "medium",
            "T1078.004",
            &c_sso,
            target,
            0.8,
            "No IAM Identity Center instance found — long-lived IAM users may proliferate without centralized federation.",
            "Enable IAM Identity Center; federate human access via IdP with MFA and short-lived credentials.",
            Evidence::new().check("list_instances", true, "empty"),
            "iam_identity_center",
            "*",
            "global",
        ));
        return findings;
    }
    for inst in instances.iter().take(3) {
        let arn = inst.instance_arn().unwrap_or("").to_string();
        if arn.is_empty() {
            continue;
        }
        graph.upsert(&format!("aws:sso:{arn}"), "iam_identity_center", "global", "internal", &[]);
        let psets = match sso
            .list_permission_sets()
            .instance_arn(&arn)
            .send()
            .await
        {
            Ok(p) => p.permission_sets().to_vec(),
            Err(_) => continue,
        };
        if psets.is_empty() {
            findings.push(posture_finding(
                Domain::Identity,
                "sso_no_permission_sets",
                "IAM Identity Center has no permission sets",
                "low",
                "T1078.004",
                &c_sso,
                target,
                0.75,
                "Identity Center instance exists but defines no permission sets — federation plane is unused.",
                "Define least-privilege permission sets and assign to accounts via SSO.",
                Evidence::new().with("instance_arn", arn.clone()),
                "iam_identity_center",
                &arn,
                "global",
            ));
        }
    }
    findings
}

// ─── Attack paths & compliance scoring ───────────────────────────────────────

