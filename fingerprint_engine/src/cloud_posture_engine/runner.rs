// ─── Entry points ──────────────────────────────────────────────────────────────

pub async fn run_cloud_posture_result(target: &str) -> EngineResult {
    run_cloud_posture_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_cloud_posture_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let opts = CloudScanOptions::from_ctx(ctx);
    let role = opts.role_arn.trim();

    if role.is_empty() {
        return EngineResult::ok(
            vec![finding_rich(
                ENGINE_ID,
                "Cross-account IAM role required for agentless CSPM",
                "info",
                "",
                "Configure aws_cross_account_role_arn (Wiz-style read-only connector role) in the scan parameters. \
                 This engine performs live AWS API inventory via STS AssumeRole — it never fabricates findings without credentials.",
                target,
                1.0,
                Evidence::new()
                    .with("required_parameter", "aws_cross_account_role_arn")
                    .with(
                        "setup_hint",
                        "Create a read-only IAM role in the customer account trusting the Weissman platform principal with sts:ExternalId.",
                    ),
            )],
            format!("{ENGINE_ID}: cross-account role required"),
        );
    }

    let cac = CrossAccountAwsConfig {
        role_arn: role.to_string(),
        external_id: opts.external_id.clone(),
        session_name: opts.session_name.clone(),
    };

    let (sdk, home_region) = match assume_role_sdk_config(&cac).await {
        Ok(v) => v,
        Err(e) => {
            return EngineResult::error(format!("STS AssumeRole failed: {e}"));
        }
    };

    let sts = aws_sdk_sts::Client::new(&sdk);
    let (account_id, principal_arn) = match sts.get_caller_identity().send().await {
        Ok(id) => (
            id.account().map(str::to_string),
            id.arn().map(str::to_string),
        ),
        Err(e) => {
            return EngineResult::error(format!("GetCallerIdentity failed after AssumeRole: {e}"));
        }
    };

    let mut graph = SecurityGraph::default();
    let mut findings: Vec<Value> = Vec::new();

    findings.push(finding_rich(
        ENGINE_ID,
        "Agentless CSPM plane authenticated",
        "info",
        "",
        &format!(
            "STS AssumeRole succeeded — scanning account {} as {} via live AWS APIs (no agents on workloads).",
            account_id.clone().unwrap_or_default(),
            principal_arn.clone().unwrap_or_default()
        ),
        target,
        1.0,
        Evidence::new()
            .with("account_id", account_id.clone().unwrap_or_default())
            .with("principal_arn", principal_arn.clone().unwrap_or_default())
            .with("home_region", home_region.as_ref())
            .check("sts_assume_role", true, "ok"),
    ));

    if opts.wants("iam") {
        findings.extend(scan_iam(&sdk, &opts, target, &mut graph).await);
        findings.extend(scan_iam_roles(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("s3") {
        findings.extend(
            scan_s3(
                &sdk,
                &opts,
                target,
                home_region.as_ref(),
                &mut graph,
            )
            .await,
        );
    }
    if opts.wants("ec2") || opts.wants("vpc") {
        findings.extend(scan_ec2_vpc(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ssm") {
        findings.extend(scan_ssm(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("lambda") && opts.check_lambda {
        findings.extend(scan_lambda(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("rds") && opts.check_rds {
        findings.extend(scan_rds(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("kms") {
        findings.extend(scan_kms(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("cloudtrail") && opts.check_cloudtrail {
        findings.extend(scan_cloudtrail(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("accessanalyzer") {
        findings.extend(scan_access_analyzer(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("guardduty") {
        findings.extend(scan_guardduty(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("config") {
        findings.extend(scan_config_recorder(&sdk, &opts, target, &mut graph).await);
    }
    if let Some(ref acct) = account_id {
        if opts.wants("account") {
            findings.extend(
                scan_account_s3_public_block(&sdk, acct, &opts, target, &mut graph).await,
            );
        }
    }
    if opts.wants("eks") {
        findings.extend(scan_eks(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("elb") {
        findings.extend(scan_elbv2(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("secrets") {
        findings.extend(scan_secrets_manager(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("messaging") {
        findings.extend(scan_messaging(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ecs") {
        findings.extend(scan_ecs(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("elasticache") {
        findings.extend(scan_elasticache(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("ecr") {
        findings.extend(scan_ecr(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("acm") {
        findings.extend(scan_acm(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("dynamodb") {
        findings.extend(scan_dynamodb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("apigateway") {
        findings.extend(scan_apigateway(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("opensearch") {
        findings.extend(scan_opensearch(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("cloudfront") {
        findings.extend(scan_cloudfront(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("route53") {
        findings.extend(scan_route53(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("eventbridge") {
        findings.extend(scan_eventbridge(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("wafv2") {
        findings.extend(scan_wafv2(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("logs") {
        findings.extend(scan_cloudwatch_logs(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("redshift") {
        findings.extend(scan_redshift(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("documentdb") {
        findings.extend(scan_documentdb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("neptune") {
        findings.extend(scan_neptune(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("memorydb") {
        findings.extend(scan_memorydb(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("backup") {
        findings.extend(scan_backup(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("organizations") {
        findings.extend(scan_organizations(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("sfn") {
        findings.extend(scan_sfn(&sdk, &opts, target, &mut graph).await);
    }
    if opts.wants("sso") {
        findings.extend(scan_sso(&sdk, &opts, target, &mut graph).await);
    }

    findings.retain(|f| {
        f.get("category").and_then(Value::as_str) == Some("summary")
            || opts.keep_severity(&finding_sev(f))
    });

    let mut attack_paths = if opts.include_attack_paths {
        synthesize_attack_paths(&findings, target, account_id.as_deref())
    } else {
        Vec::new()
    };
    if opts.include_attack_paths && opts.check_graph_paths {
        attack_paths.extend(synthesize_graph_attack_paths(
            &graph,
            target,
            account_id.as_deref(),
        ));
    }

    let summary = build_summary(
        target,
        account_id.as_deref(),
        principal_arn.as_deref(),
        &findings,
        &attack_paths,
        &graph,
        &opts,
    );

    findings.extend(attack_paths);
    findings.push(summary);

    EngineResult::ok(findings, format!("{ENGINE_ID}: scan complete"))
}

pub async fn run_cloud_posture(target: &str) {
    print_result(run_cloud_posture_result(target).await);
}
