"""
CSPM Compliance Engine
=====================
Checks cloud configurations against CIS Benchmarks and industry standards.

Supported Benchmarks:
- CIS AWS Foundations Benchmark v1.5
- CIS Azure Foundations Benchmark v1.5 (planned)
- CIS GCP Foundations Benchmark v1.3 (planned)

MITRE ATT&CK: T1580 (Cloud Infrastructure Discovery), T1552 (Unsecured Credentials)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger("weissman.cspm_compliance")


class ComplianceStatus(Enum):
    """Compliance check status."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ComplianceCheck:
    """Represents a compliance check result."""
    check_id: str
    title: str
    severity: str  # "critical", "high", "medium", "low"
    status: ComplianceStatus
    description: str
    remediation: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    benchmark: str = "CIS AWS v1.5"


class CSPMComplianceEngine:
    """
    Cloud Security Posture Management compliance checker.

    Validates cloud configurations against industry benchmarks.
    """

    def __init__(self):
        self.checks: List[ComplianceCheck] = []

    def check_aws_cis_benchmarks(self, profile: str = "default") -> List[ComplianceCheck]:
        """
        Check AWS environment against CIS AWS Foundations Benchmark.

        Priority checks:
        - IAM password policy
        - Root account usage
        - MFA enforcement
        - S3 bucket encryption
        - CloudTrail logging
        - VPC security groups
        """
        checks = []

        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            logger.warning("boto3 not installed")
            return checks

        try:
            session = boto3.Session(profile_name=profile)

            # CIS 1.x - IAM checks
            checks.extend(self._check_aws_iam(session))

            # CIS 2.x - Storage checks
            checks.extend(self._check_aws_s3(session))

            # CIS 3.x - Logging checks
            checks.extend(self._check_aws_cloudtrail(session))

            # CIS 4.x - Monitoring checks
            checks.extend(self._check_aws_monitoring(session))

            # CIS 5.x - Networking checks
            checks.extend(self._check_aws_networking(session))

        except NoCredentialsError:
            logger.error("AWS credentials not found")
        except Exception as e:
            logger.error(f"CIS benchmark check failed: {e}")

        self.checks.extend(checks)
        return checks

    def _check_aws_iam(self, session) -> List[ComplianceCheck]:
        """CIS 1.x - IAM Configuration checks."""
        checks = []

        try:
            iam = session.client('iam')

            # CIS 1.5 - Ensure IAM password policy requires minimum length of 14
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                min_length = policy.get('MinimumPasswordLength', 0)

                if min_length >= 14:
                    checks.append(ComplianceCheck(
                        check_id="CIS-1.5",
                        title="IAM password policy requires minimum length of 14",
                        severity="medium",
                        status=ComplianceStatus.PASS,
                        description=f"Password minimum length is {min_length}",
                        remediation="No action needed",
                        benchmark="CIS AWS v1.5"
                    ))
                else:
                    checks.append(ComplianceCheck(
                        check_id="CIS-1.5",
                        title="IAM password policy requires minimum length of 14",
                        severity="medium",
                        status=ComplianceStatus.FAIL,
                        description=f"Password minimum length is {min_length}, should be >= 14",
                        remediation="Update IAM password policy: aws iam update-account-password-policy --minimum-password-length 14",
                        benchmark="CIS AWS v1.5"
                    ))
            except ClientError:
                checks.append(ComplianceCheck(
                    check_id="CIS-1.5",
                    title="IAM password policy requires minimum length of 14",
                    severity="medium",
                    status=ComplianceStatus.FAIL,
                    description="No password policy configured",
                    remediation="Create IAM password policy with minimum length 14",
                    benchmark="CIS AWS v1.5"
                ))

            # CIS 1.10 - Ensure multi-factor authentication (MFA) is enabled for root account
            try:
                summary = iam.get_account_summary()['SummaryMap']
                root_mfa = summary.get('AccountMFAEnabled', 0)

                if root_mfa == 1:
                    checks.append(ComplianceCheck(
                        check_id="CIS-1.10",
                        title="MFA enabled for root account",
                        severity="critical",
                        status=ComplianceStatus.PASS,
                        description="Root account has MFA enabled",
                        remediation="No action needed",
                        benchmark="CIS AWS v1.5"
                    ))
                else:
                    checks.append(ComplianceCheck(
                        check_id="CIS-1.10",
                        title="MFA enabled for root account",
                        severity="critical",
                        status=ComplianceStatus.FAIL,
                        description="Root account does not have MFA enabled",
                        remediation="Enable MFA for root account in AWS Console",
                        benchmark="CIS AWS v1.5"
                    ))
            except Exception as e:
                logger.error(f"Failed to check root MFA: {e}")

            # CIS 1.12 - Ensure credentials unused for 90 days are disabled
            try:
                cred_report = iam.generate_credential_report()
                report = iam.get_credential_report()['Content'].decode('utf-8')

                # Parse CSV credential report
                lines = report.split('\n')
                for line in lines[1:]:  # Skip header
                    if not line.strip():
                        continue

                    parts = line.split(',')
                    if len(parts) < 5:
                        continue

                    username = parts[0]
                    password_last_used = parts[4]

                    # Check if password unused for 90+ days
                    if password_last_used and password_last_used not in ("N/A", "no_information", ""):
                        try:
                            last_used_dt = datetime.fromisoformat(
                                password_last_used.replace("Z", "+00:00")
                            )
                            now = datetime.now(timezone.utc)
                            days_unused = (now - last_used_dt).days
                            if days_unused >= 90:
                                checks.append(ComplianceCheck(
                                    check_id="CIS-1.12",
                                    title="Credentials unused for 90+ days disabled",
                                    severity="medium",
                                    status=ComplianceStatus.FAIL,
                                    description=(
                                        f"User '{username}' password unused for {days_unused} days "
                                        f"(last used: {password_last_used})"
                                    ),
                                    remediation=(
                                        f"Disable or delete credentials for IAM user '{username}': "
                                        f"aws iam delete-login-profile --user-name {username}"
                                    ),
                                    resource_id=username,
                                    resource_type="iam_user",
                                    benchmark="CIS AWS v1.5",
                                ))
                        except (ValueError, TypeError):
                            logger.debug("Could not parse password_last_used date for %s", username)

            except Exception as e:
                logger.error(f"Failed to check credential usage: {e}")

        except Exception as e:
            logger.error(f"IAM checks failed: {e}")

        return checks

    def _check_aws_s3(self, session) -> List[ComplianceCheck]:
        """CIS 2.x - S3 Configuration checks."""
        checks = []

        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']

                # CIS 2.1.1 - Ensure S3 bucket access logging is enabled
                try:
                    logging_config = s3.get_bucket_logging(Bucket=bucket_name)

                    if 'LoggingEnabled' in logging_config:
                        checks.append(ComplianceCheck(
                            check_id="CIS-2.1.1",
                            title="S3 bucket access logging enabled",
                            severity="low",
                            status=ComplianceStatus.PASS,
                            description=f"Bucket {bucket_name} has access logging enabled",
                            remediation="No action needed",
                            resource_id=bucket_name,
                            resource_type="s3_bucket",
                            benchmark="CIS AWS v1.5"
                        ))
                    else:
                        checks.append(ComplianceCheck(
                            check_id="CIS-2.1.1",
                            title="S3 bucket access logging enabled",
                            severity="low",
                            status=ComplianceStatus.FAIL,
                            description=f"Bucket {bucket_name} does not have access logging enabled",
                            remediation=f"aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status file://logging.json",
                            resource_id=bucket_name,
                            resource_type="s3_bucket",
                            benchmark="CIS AWS v1.5"
                        ))
                except Exception as e:
                    logger.error(f"Failed to check S3 logging for {bucket_name}: {e}")

                # CIS 2.1.2 - Ensure S3 bucket has encryption enabled
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)

                    checks.append(ComplianceCheck(
                        check_id="CIS-2.1.2",
                        title="S3 bucket encryption enabled",
                        severity="high",
                        status=ComplianceStatus.PASS,
                        description=f"Bucket {bucket_name} has encryption enabled",
                        remediation="No action needed",
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        benchmark="CIS AWS v1.5"
                    ))
                except ClientError:
                    checks.append(ComplianceCheck(
                        check_id="CIS-2.1.2",
                        title="S3 bucket encryption enabled",
                        severity="high",
                        status=ComplianceStatus.FAIL,
                        description=f"Bucket {bucket_name} does not have encryption enabled",
                        remediation=f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration file://encryption.json",
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        benchmark="CIS AWS v1.5"
                    ))

        except Exception as e:
            logger.error(f"S3 checks failed: {e}")

        return checks

    def _check_aws_cloudtrail(self, session) -> List[ComplianceCheck]:
        """CIS 3.x - CloudTrail Configuration checks."""
        checks = []

        try:
            cloudtrail = session.client('cloudtrail')

            # CIS 3.1 - Ensure CloudTrail is enabled in all regions
            trails = cloudtrail.describe_trails()['trailList']

            multi_region_trail = any(trail.get('IsMultiRegionTrail', False) for trail in trails)

            if multi_region_trail:
                checks.append(ComplianceCheck(
                    check_id="CIS-3.1",
                    title="CloudTrail enabled in all regions",
                    severity="high",
                    status=ComplianceStatus.PASS,
                    description="Multi-region CloudTrail is configured",
                    remediation="No action needed",
                    benchmark="CIS AWS v1.5"
                ))
            else:
                checks.append(ComplianceCheck(
                    check_id="CIS-3.1",
                    title="CloudTrail enabled in all regions",
                    severity="high",
                    status=ComplianceStatus.FAIL,
                    description="No multi-region CloudTrail found",
                    remediation="Create a multi-region CloudTrail: aws cloudtrail create-trail --name all-regions --is-multi-region-trail",
                    benchmark="CIS AWS v1.5"
                ))

        except Exception as e:
            logger.error(f"CloudTrail checks failed: {e}")

        return checks

    def _check_aws_monitoring(self, session) -> List[ComplianceCheck]:
        """CIS 4.x - Monitoring Configuration checks."""
        checks = []

        try:
            logs = session.client('logs')
            cloudwatch = session.client('cloudwatch')

            # CIS 4.1 - Ensure log metric filter and alarm exist for unauthorized API calls
            _REQUIRED_FILTERS = [
                {
                    "check_id": "CIS-4.1",
                    "title": "Metric filter for unauthorized API calls",
                    "pattern_fragment": "errorCode",
                    "description": "No CloudWatch metric filter/alarm for unauthorized API calls",
                    "remediation": (
                        "Create a metric filter matching { ($.errorCode = \"*UnauthorizedAccess*\") || "
                        "($.errorCode = \"AccessDenied\") } and a corresponding alarm"
                    ),
                },
                {
                    "check_id": "CIS-4.2",
                    "title": "Metric filter for Console sign-in without MFA",
                    "pattern_fragment": "ConsoleLogin",
                    "description": "No CloudWatch metric filter/alarm for console sign-ins without MFA",
                    "remediation": (
                        "Create a metric filter matching { ($.eventName = \"ConsoleLogin\") && "
                        "($.additionalEventData.MFAUsed != \"Yes\") } and a corresponding alarm"
                    ),
                },
                {
                    "check_id": "CIS-4.3",
                    "title": "Metric filter for root account usage",
                    "pattern_fragment": "userIdentity.type = \"Root\"",
                    "description": "No CloudWatch metric filter/alarm for root account usage",
                    "remediation": (
                        "Create a metric filter matching { $.userIdentity.type = \"Root\" && "
                        "$.userIdentity.invokedBy NOT EXISTS } and a corresponding alarm"
                    ),
                },
            ]

            try:
                log_groups = logs.describe_log_groups()
                all_metric_filters = []
                for lg in log_groups.get("logGroups", []):
                    lg_name = lg["logGroupName"]
                    filters_resp = logs.describe_metric_filters(logGroupName=lg_name)
                    all_metric_filters.extend(filters_resp.get("metricFilters", []))

                # Collect alarm names from all metric transformations
                alarm_metric_names = set()
                alarms_resp = cloudwatch.describe_alarms()
                for alarm in alarms_resp.get("MetricAlarms", []):
                    alarm_metric_names.add(alarm.get("MetricName", ""))

                for req in _REQUIRED_FILTERS:
                    pattern_found = any(
                        req["pattern_fragment"] in (mf.get("filterPattern") or "")
                        for mf in all_metric_filters
                    )
                    alarm_found = False
                    if pattern_found:
                        # Verify there is an alarm for at least one transformation metric
                        for mf in all_metric_filters:
                            if req["pattern_fragment"] in (mf.get("filterPattern") or ""):
                                for tr in mf.get("metricTransformations", []):
                                    if tr.get("metricName") in alarm_metric_names:
                                        alarm_found = True
                                        break

                    if pattern_found and alarm_found:
                        checks.append(ComplianceCheck(
                            check_id=req["check_id"],
                            title=req["title"],
                            severity="medium",
                            status=ComplianceStatus.PASS,
                            description=f"{req['title']} is configured",
                            remediation="No action needed",
                            benchmark="CIS AWS v1.5",
                        ))
                    else:
                        checks.append(ComplianceCheck(
                            check_id=req["check_id"],
                            title=req["title"],
                            severity="medium",
                            status=ComplianceStatus.FAIL,
                            description=req["description"],
                            remediation=req["remediation"],
                            benchmark="CIS AWS v1.5",
                        ))

            except Exception as e:
                logger.error(f"Metric filter checks failed: {e}")

        except Exception as e:
            logger.error(f"Monitoring checks failed: {e}")

        return checks

    def _check_aws_networking(self, session) -> List[ComplianceCheck]:
        """CIS 5.x - Networking Configuration checks."""
        checks = []

        try:
            ec2 = session.client('ec2')

            # CIS 5.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')

                    # Check for SSH (22) or RDP (3389) open to 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')

                        if cidr == '0.0.0.0/0':
                            if from_port == 22 or (from_port is None and to_port == 22):
                                checks.append(ComplianceCheck(
                                    check_id="CIS-5.1",
                                    title="No security group allows SSH from 0.0.0.0/0",
                                    severity="critical",
                                    status=ComplianceStatus.FAIL,
                                    description=f"Security group {sg_id} ({sg_name}) allows SSH from anywhere",
                                    remediation=f"Remove 0.0.0.0/0 ingress rule for port 22 in {sg_id}",
                                    resource_id=sg_id,
                                    resource_type="security_group",
                                    benchmark="CIS AWS v1.5"
                                ))

                            if from_port == 3389 or (from_port is None and to_port == 3389):
                                checks.append(ComplianceCheck(
                                    check_id="CIS-5.2",
                                    title="No security group allows RDP from 0.0.0.0/0",
                                    severity="critical",
                                    status=ComplianceStatus.FAIL,
                                    description=f"Security group {sg_id} ({sg_name}) allows RDP from anywhere",
                                    remediation=f"Remove 0.0.0.0/0 ingress rule for port 3389 in {sg_id}",
                                    resource_id=sg_id,
                                    resource_type="security_group",
                                    benchmark="CIS AWS v1.5"
                                ))

        except Exception as e:
            logger.error(f"Networking checks failed: {e}")

        return checks

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report."""
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.status == ComplianceStatus.PASS)
        failed = sum(1 for c in self.checks if c.status == ComplianceStatus.FAIL)
        errors = sum(1 for c in self.checks if c.status == ComplianceStatus.ERROR)

        compliance_score = (passed / total * 100) if total > 0 else 0

        critical_failures = [c for c in self.checks if c.severity == "critical" and c.status == ComplianceStatus.FAIL]
        high_failures = [c for c in self.checks if c.severity == "high" and c.status == ComplianceStatus.FAIL]

        return {
            "compliance_score": round(compliance_score, 2),
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "critical_failures": len(critical_failures),
            "high_failures": len(high_failures),
            "checks": [
                {
                    "id": c.check_id,
                    "title": c.title,
                    "severity": c.severity,
                    "status": c.status.value,
                    "description": c.description,
                    "remediation": c.remediation,
                    "resource_id": c.resource_id,
                    "resource_type": c.resource_type,
                    "benchmark": c.benchmark
                }
                for c in self.checks
            ]
        }


def run_cspm_compliance_check(provider: str = "aws", profile: str = "default") -> Dict[str, Any]:
    """
    Run CSPM compliance checks.

    Args:
        provider: Cloud provider ("aws", "azure", "gcp")
        profile: AWS profile name (for AWS only)

    Returns:
        Compliance report with findings
    """
    engine = CSPMComplianceEngine()

    if provider == "aws":
        engine.check_aws_cis_benchmarks(profile=profile)
    elif provider == "azure":
        logger.info("Azure compliance checks not yet implemented")
    elif provider == "gcp":
        logger.info("GCP compliance checks not yet implemented")
    else:
        return {"error": f"Unknown provider: {provider}"}

    return engine.generate_compliance_report()
