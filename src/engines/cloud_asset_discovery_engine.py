"""
Cloud Asset Discovery Engine
============================
Discovers cloud resources across AWS, Azure, and GCP.

This is the foundation for Cloud Security Posture Management (CSPM).
Future enhancements will add:
- Compliance checking (CIS benchmarks)
- Misconfiguration detection
- Security group analysis
- IAM permission analysis

MITRE ATT&CK: T1580 (Cloud Infrastructure Discovery)
"""

import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

logger = logging.getLogger("weissman.cloud_asset_discovery")


@dataclass
class CloudAsset:
    """Represents a discovered cloud asset."""
    provider: str  # "aws", "azure", "gcp"
    resource_type: str  # "ec2", "s3", "vm", "storage"
    resource_id: str
    resource_name: str
    region: str
    tags: Dict[str, str]
    created_at: Optional[str] = None
    public_exposure: bool = False
    encryption_enabled: bool = False
    compliance_issues: List[str] = None

    def __post_init__(self):
        if self.compliance_issues is None:
            self.compliance_issues = []


class CloudAssetDiscovery:
    """
    Cloud asset discovery scanner.

    Currently supports discovery via cloud provider APIs.
    Requires appropriate credentials configured in environment.
    """

    def __init__(self):
        self.discovered_assets: List[CloudAsset] = []

    def discover_aws_assets(self, profile: str = "default") -> List[CloudAsset]:
        """
        Discover AWS assets.

        Requires: AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        or AWS CLI profile.

        Discovers:
        - EC2 instances
        - S3 buckets
        - RDS databases
        - Lambda functions
        - Load balancers
        - Security groups
        """
        assets = []

        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            logger.warning("boto3 not installed. Run: pip install boto3")
            return assets

        try:
            session = boto3.Session(profile_name=profile)

            # Discover EC2 instances
            assets.extend(self._discover_aws_ec2(session))

            # Discover S3 buckets
            assets.extend(self._discover_aws_s3(session))

            # Discover RDS databases
            assets.extend(self._discover_aws_rds(session))

            # Discover Lambda functions
            assets.extend(self._discover_aws_lambda(session))

        except NoCredentialsError:
            logger.error("AWS credentials not found")
        except ClientError as e:
            logger.error(f"AWS discovery failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during AWS discovery: {e}")

        self.discovered_assets.extend(assets)
        return assets

    def _discover_aws_ec2(self, session) -> List[CloudAsset]:
        """Discover EC2 instances."""
        assets = []

        try:
            ec2 = session.client('ec2')
            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]

            for region in regions:
                ec2_regional = session.client('ec2', region_name=region)
                response = ec2_regional.describe_instances()

                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        public_ip = instance.get('PublicIpAddress')

                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

                        asset = CloudAsset(
                            provider="aws",
                            resource_type="ec2",
                            resource_id=instance['InstanceId'],
                            resource_name=tags.get('Name', instance['InstanceId']),
                            region=region,
                            tags=tags,
                            created_at=str(instance.get('LaunchTime')),
                            public_exposure=bool(public_ip),
                            encryption_enabled=False  # Check EBS volumes separately
                        )

                        # Check for common misconfigurations
                        if public_ip and not instance.get('IamInstanceProfile'):
                            asset.compliance_issues.append("Public EC2 without IAM role")

                        assets.append(asset)

        except Exception as e:
            logger.error(f"EC2 discovery failed: {e}")

        return assets

    def _discover_aws_s3(self, session) -> List[CloudAsset]:
        """Discover S3 buckets."""
        assets = []

        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()

            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']

                try:
                    # Check if bucket is public
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    is_public = not all([
                        public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'],
                        public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy'],
                        public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'],
                        public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets'],
                    ])
                except:
                    is_public = True  # Assume public if can't check

                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    encrypted = True
                except:
                    encrypted = False

                # Get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location['LocationConstraint'] or 'us-east-1'
                except:
                    region = 'unknown'

                asset = CloudAsset(
                    provider="aws",
                    resource_type="s3",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=region,
                    tags={},
                    created_at=str(bucket.get('CreationDate')),
                    public_exposure=is_public,
                    encryption_enabled=encrypted
                )

                # Compliance checks
                if is_public:
                    asset.compliance_issues.append("S3 bucket is publicly accessible")
                if not encrypted:
                    asset.compliance_issues.append("S3 bucket encryption not enabled")

                assets.append(asset)

        except Exception as e:
            logger.error(f"S3 discovery failed: {e}")

        return assets

    def _discover_aws_rds(self, session) -> List[CloudAsset]:
        """Discover RDS databases."""
        assets = []

        try:
            rds = session.client('rds')
            regions = [r['RegionName'] for r in session.client('ec2').describe_regions()['Regions']]

            for region in regions:
                rds_regional = session.client('rds', region_name=region)
                response = rds_regional.describe_db_instances()

                for db in response['DBInstances']:
                    asset = CloudAsset(
                        provider="aws",
                        resource_type="rds",
                        resource_id=db['DBInstanceIdentifier'],
                        resource_name=db['DBInstanceIdentifier'],
                        region=region,
                        tags={},
                        created_at=str(db.get('InstanceCreateTime')),
                        public_exposure=db.get('PubliclyAccessible', False),
                        encryption_enabled=db.get('StorageEncrypted', False)
                    )

                    # Compliance checks
                    if db.get('PubliclyAccessible'):
                        asset.compliance_issues.append("RDS database is publicly accessible")
                    if not db.get('StorageEncrypted'):
                        asset.compliance_issues.append("RDS encryption not enabled")
                    if not db.get('MultiAZ'):
                        asset.compliance_issues.append("RDS Multi-AZ not enabled")

                    assets.append(asset)

        except Exception as e:
            logger.error(f"RDS discovery failed: {e}")

        return assets

    def _discover_aws_lambda(self, session) -> List[CloudAsset]:
        """Discover Lambda functions."""
        assets = []

        try:
            regions = [r['RegionName'] for r in session.client('ec2').describe_regions()['Regions']]

            for region in regions:
                lambda_client = session.client('lambda', region_name=region)
                response = lambda_client.list_functions()

                for func in response['Functions']:
                    asset = CloudAsset(
                        provider="aws",
                        resource_type="lambda",
                        resource_id=func['FunctionArn'],
                        resource_name=func['FunctionName'],
                        region=region,
                        tags={},
                        created_at=func.get('LastModified'),
                        public_exposure=False,  # Check function URLs separately
                        encryption_enabled=False
                    )

                    # Check for public function URLs
                    try:
                        url_config = lambda_client.get_function_url_config(FunctionName=func['FunctionName'])
                        if url_config:
                            asset.public_exposure = True
                            asset.compliance_issues.append("Lambda function has public URL")
                    except:
                        pass

                    assets.append(asset)

        except Exception as e:
            logger.error(f"Lambda discovery failed: {e}")

        return assets

    def discover_azure_assets(self) -> List[CloudAsset]:
        """
        Discover Azure assets.

        Requires: Azure credentials configured (AZURE_SUBSCRIPTION_ID, etc.)

        Discovers:
        - Virtual Machines
        - Storage Accounts
        - SQL Databases
        - App Services
        """
        assets = []

        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.resource import ResourceManagementClient
        except ImportError:
            logger.warning("Azure SDK not installed. Run: pip install azure-identity azure-mgmt-compute azure-mgmt-storage azure-mgmt-resource")
            return assets

        # TODO: Implement Azure discovery
        logger.info("Azure discovery not yet implemented")

        return assets

    def discover_gcp_assets(self, project_id: str = None) -> List[CloudAsset]:
        """
        Discover GCP assets.

        Requires: GCP credentials configured (GOOGLE_APPLICATION_CREDENTIALS)

        Discovers:
        - Compute Engine instances
        - Cloud Storage buckets
        - Cloud SQL instances
        - Cloud Functions
        """
        assets = []

        try:
            from google.cloud import compute_v1
            from google.cloud import storage
        except ImportError:
            logger.warning("Google Cloud SDK not installed. Run: pip install google-cloud-compute google-cloud-storage")
            return assets

        # TODO: Implement GCP discovery
        logger.info("GCP discovery not yet implemented")

        return assets

    def generate_report(self) -> Dict[str, Any]:
        """Generate asset discovery report."""
        total = len(self.discovered_assets)
        by_provider = {}
        by_type = {}
        public_assets = 0
        unencrypted_assets = 0
        assets_with_issues = 0

        for asset in self.discovered_assets:
            by_provider[asset.provider] = by_provider.get(asset.provider, 0) + 1
            by_type[asset.resource_type] = by_type.get(asset.resource_type, 0) + 1

            if asset.public_exposure:
                public_assets += 1
            if not asset.encryption_enabled:
                unencrypted_assets += 1
            if asset.compliance_issues:
                assets_with_issues += 1

        return {
            "total_assets": total,
            "by_provider": by_provider,
            "by_type": by_type,
            "public_assets": public_assets,
            "unencrypted_assets": unencrypted_assets,
            "assets_with_compliance_issues": assets_with_issues,
            "top_issues": self._get_top_issues()
        }

    def _get_top_issues(self) -> List[Dict[str, Any]]:
        """Get top compliance issues."""
        issue_counts = {}

        for asset in self.discovered_assets:
            for issue in asset.compliance_issues:
                issue_counts[issue] = issue_counts.get(issue, 0) + 1

        return [
            {"issue": issue, "count": count}
            for issue, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]


def run_cloud_asset_discovery(provider: str = "aws", profile: str = "default") -> Dict[str, Any]:
    """
    Run cloud asset discovery.

    Args:
        provider: Cloud provider ("aws", "azure", "gcp")
        profile: AWS profile name (for AWS only)

    Returns:
        Discovery report with findings
    """
    discovery = CloudAssetDiscovery()

    if provider == "aws":
        discovery.discover_aws_assets(profile=profile)
    elif provider == "azure":
        discovery.discover_azure_assets()
    elif provider == "gcp":
        discovery.discover_gcp_assets()
    else:
        logger.error(f"Unknown provider: {provider}")
        return {"error": f"Unknown provider: {provider}"}

    report = discovery.generate_report()
    report["assets"] = [
        {
            "provider": a.provider,
            "type": a.resource_type,
            "id": a.resource_id,
            "name": a.resource_name,
            "region": a.region,
            "public": a.public_exposure,
            "encrypted": a.encryption_enabled,
            "issues": a.compliance_issues
        }
        for a in discovery.discovered_assets
    ]

    return report
