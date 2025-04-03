import boto3
import json
import argparse
import os
import sys
import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('aws-securescan')

# Hardcoded credentials (NOT RECOMMENDED for production use)
AWS_ACCESS_KEY_ID = 'AKIATFQR7NSCVV554SU6'
AWS_SECRET_ACCESS_KEY = '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'

class AWSSecureScan:
    def __init__(self, profile=None, region='us-east-1'):
        self.findings = []
        self.region = region
        self.profile = profile
        self.session = self._create_session()
        self.account_id = self._get_account_id()
        
    def _create_session(self):
        """Create a boto3 session using either hardcoded credentials or a profile"""
        if self.profile:
            return boto3.Session(profile_name=self.profile, region_name=self.region)
        else:
            return boto3.Session(
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=self.region
            )
    
    def _get_account_id(self):
        """Get the AWS account ID"""
        try:
            sts_client = self.session.client('sts')
            return sts_client.get_caller_identity()["Account"]
        except Exception as e:
            logger.error(f"Failed to get AWS account ID: {str(e)}")
            sys.exit(1)
    
    def add_finding(self, service, severity, title, description, resource_id, recommendation):
        """Add a security finding to the report"""
        finding = {
            "service": service,
            "severity": severity,
            "title": title,
            "description": description,
            "resource_id": resource_id,
            "recommendation": recommendation,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.findings.append(finding)
        logger.info(f"Finding added: {title} - {severity} - {resource_id}")
    
    def scan_s3_buckets(self):
        """Scan S3 buckets for security issues"""
        logger.info("Scanning S3 buckets...")
        s3_client = self.session.client('s3')
        
        try:
            buckets = s3_client.list_buckets()
            
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                
                # Check public access block
                try:
                    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                    block_config = public_access_block['PublicAccessBlockConfiguration']
                    
                    if not all([
                        block_config.get('BlockPublicAcls', False),
                        block_config.get('IgnorePublicAcls', False),
                        block_config.get('BlockPublicPolicy', False),
                        block_config.get('RestrictPublicBuckets', False)
                    ]):
                        self.add_finding(
                            service="S3",
                            severity="HIGH",
                            title="S3 Bucket Missing Public Access Block",
                            description=f"S3 bucket {bucket_name} does not have all public access block settings enabled.",
                            resource_id=bucket_name,
                            recommendation="Enable all four public access block settings for this S3 bucket."
                        )
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self.add_finding(
                            service="S3",
                            severity="HIGH",
                            title="S3 Bucket Missing Public Access Block Configuration",
                            description=f"S3 bucket {bucket_name} does not have public access block configuration.",
                            resource_id=bucket_name,
                            recommendation="Configure public access block for this S3 bucket."
                        )
                
                # Check bucket policy
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_json = json.loads(policy['Policy'])
                    
                    # Basic policy analysis (simplified)
                    for statement in policy_json.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and (
                            statement.get('Principal') == '*' or 
                            statement.get('Principal', {}).get('AWS') == '*'
                        ):
                            self.add_finding(
                                service="S3",
                                severity="CRITICAL",
                                title="S3 Bucket Has Public Policy",
                                description=f"S3 bucket {bucket_name} has a policy that grants public access.",
                                resource_id=bucket_name,
                                recommendation="Review and restrict the bucket policy to only necessary permissions."
                            )
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
                
                # Check bucket encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self.add_finding(
                            service="S3",
                            severity="MEDIUM",
                            title="S3 Bucket Missing Default Encryption",
                            description=f"S3 bucket {bucket_name} does not have default encryption enabled.",
                            resource_id=bucket_name,
                            recommendation="Enable default encryption for this S3 bucket."
                        )
                
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {str(e)}")
    
    def scan_ec2_instances(self):
        """Scan EC2 instances for security issues"""
        logger.info("Scanning EC2 instances...")
        ec2_client = self.session.client('ec2')
        
        try:
            # Get all EC2 instances
            paginator = ec2_client.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        
                        # Check if instance is in a public subnet
                        for interface in instance.get('NetworkInterfaces', []):
                            if interface.get('Association', {}).get('PublicIp'):
                                # Check security groups
                                for sg in instance.get('SecurityGroups', []):
                                    sg_id = sg['GroupId']
                                    sg_info = ec2_client.describe_security_groups(GroupIds=[sg_id])
                                    
                                    for sg_detail in sg_info['SecurityGroups']:
                                        for rule in sg_detail.get('IpPermissions', []):
                                            for ip_range in rule.get('IpRanges', []):
                                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                                    if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                                                        self.add_finding(
                                                            service="EC2",
                                                            severity="HIGH",
                                                            title="EC2 Instance With Public SSH Access",
                                                            description=f"EC2 instance {instance_id} has SSH (port 22) open to the internet.",
                                                            resource_id=instance_id,
                                                            recommendation="Restrict SSH access to specific IP addresses or use a bastion host."
                                                        )
                                                    
                                                    if rule.get('FromPort') == 3389 or rule.get('ToPort') == 3389:
                                                        self.add_finding(
                                                            service="EC2",
                                                            severity="HIGH",
                                                            title="EC2 Instance With Public RDP Access",
                                                            description=f"EC2 instance {instance_id} has RDP (port 3389) open to the internet.",
                                                            resource_id=instance_id,
                                                            recommendation="Restrict RDP access to specific IP addresses or use a bastion host."
                                                        )
                        
                        # Check if instance has IMDSv2 enabled
                        if instance.get('MetadataOptions', {}).get('HttpTokens') != 'required':
                            self.add_finding(
                                service="EC2",
                                severity="MEDIUM",
                                title="EC2 Instance Without IMDSv2",
                                description=f"EC2 instance {instance_id} does not require IMDSv2 (token-based metadata).",
                                resource_id=instance_id,
                                recommendation="Enable IMDSv2 by setting HttpTokens to 'required'."
                            )
        
        except Exception as e:
            logger.error(f"Error scanning EC2 instances: {str(e)}")
    
    def scan_iam(self):
        """Scan IAM for security issues"""
        logger.info("Scanning IAM...")
        iam_client = self.session.client('iam')
        
        try:
            # Check for root account MFA
            summary = iam_client.get_account_summary()
            if summary['SummaryMap']['AccountMFAEnabled'] != 1:
                self.add_finding(
                    service="IAM",
                    severity="CRITICAL",
                    title="Root Account Missing MFA",
                    description="The AWS root account does not have MFA enabled.",
                    resource_id="root",
                    recommendation="Enable MFA for the root account immediately."
                )
            
            # Check IAM users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Check for console access without MFA
                    login_profile = None
                    try:
                        login_profile = iam_client.get_login_profile(UserName=username)
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchEntity':
                            logger.warning(f"Error checking login profile for {username}: {str(e)}")
                    
                    if login_profile:
                        # User has console access, check for MFA
                        mfa_devices = iam_client.list_mfa_devices(UserName=username)
                        if not mfa_devices['MFADevices']:
                            self.add_finding(
                                service="IAM",
                                severity="HIGH",
                                title="IAM User Without MFA",
                                description=f"IAM user {username} has console access but no MFA device configured.",
                                resource_id=username,
                                recommendation="Enable MFA for this IAM user."
                            )
                    
                    # Check for access keys
                    access_keys = iam_client.list_access_keys(UserName=username)
                    for key in access_keys['AccessKeyMetadata']:
                        key_id = key['AccessKeyId']
                        
                        # Check key age
                        key_created = key['CreateDate']
                        key_age = (datetime.datetime.now(key_created.tzinfo) - key_created).days
                        
                        if key_age > 90:
                            self.add_finding(
                                service="IAM",
                                severity="MEDIUM",
                                title="IAM Access Key Age",
                                description=f"IAM user {username} has an access key {key_id} that is {key_age} days old.",
                                resource_id=f"{username}/{key_id}",
                                recommendation="Rotate access keys that are older than 90 days."
                            )
            
            # Check for overly permissive IAM policies
            paginator = iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']
                    
                    # Get policy details
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_doc = policy_version['PolicyVersion']['Document']
                    
                    # Check for * permissions
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if not isinstance(actions, list):
                                actions = [actions]
                            
                            resources = statement.get('Resource', [])
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            if '*' in actions and '*' in resources:
                                self.add_finding(
                                    service="IAM",
                                    severity="CRITICAL",
                                    title="Overly Permissive IAM Policy",
                                    description=f"IAM policy {policy_name} grants '*' permissions on '*' resources.",
                                    resource_id=policy_arn,
                                    recommendation="Update the policy to use more specific actions and resources."
                                )
        
        except Exception as e:
            logger.error(f"Error scanning IAM: {str(e)}")
    
    def scan(self):
        """Run all security scans"""
        logger.info(f"Starting security scan for AWS account {self.account_id}...")
        
        # Run scans in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            executor.submit(self.scan_s3_buckets)
            executor.submit(self.scan_ec2_instances)
            executor.submit(self.scan_iam)
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate a security report based on findings"""
        logger.info("Generating security report...")
        
        # Count findings by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for finding in self.findings:
            severity = finding["severity"]
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        report = {
            "account_id": self.account_id,
            "scan_time": datetime.datetime.now().isoformat(),
            "findings_summary": severity_counts,
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        return report

def save_report(report, output_file=None):
    """Save the report to a file"""
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file = f"aws-securescan-report-{report['account_id']}-{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved to {output_file}")
    return output_file

def print_report_summary(report):
    """Print a summary of the report"""
    print("\n" + "=" * 80)
    print(f"AWS-SecureScan Report for Account: {report['account_id']}")
    print(f"Scan Time: {report['scan_time']}")
    print("=" * 80)
    
    summary = report['findings_summary']
    print("\nFindings Summary:")
    print(f"  CRITICAL: {summary['CRITICAL']}")
    print(f"  HIGH:     {summary['HIGH']}")
    print(f"  MEDIUM:   {summary['MEDIUM']}")
    print(f"  LOW:      {summary['LOW']}")
    print(f"  TOTAL:    {report['total_findings']}")
    
    if report['total_findings'] > 0:
        print("\nTop Findings:")
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            report['findings'], 
            key=lambda x: (severity_order.get(x['severity'], 4), x['title'])
        )
        
        for i, finding in enumerate(sorted_findings[:5]):
            print(f"  {i+1}. [{finding['severity']}] {finding['title']} - {finding['resource_id']}")
        
        if report['total_findings'] > 5:
            print(f"  ... and {report['total_findings'] - 5} more findings.")
    
    print("\nSee the full report for detailed information and recommendations.")
    print("=" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(description='AWS-SecureScan - Security Scanner for AWS')
    parser.add_argument('--profile', type=str, help='AWS CLI profile name')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS region')
    parser.add_argument('--output', type=str, help='Output file for the report')
    args = parser.parse_args()
    
    # Create and run scanner
    scanner = AWSSecureScan(profile=args.profile, region=args.region)
    report = scanner.scan()
    
    # Save and display report
    output_file = save_report(report, args.output)
    print_report_summary(report)
    print(f"Full report saved to: {output_file}")

if __name__ == "__main__":
    main()
