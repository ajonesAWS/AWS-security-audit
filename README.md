AWS-SecureScan is a simple, powerful tool designed to scan an AWS account for security misconfigurations and vulnerabilities. It audits your AWS environment for common security issues and generates a detailed report highlighting potential risks, best practices violations, and recommendations for improving your account's security posture.

**Features**
- Comprehensive Security Audit: Scans critical AWS services like EC2, S3, IAM, and more.
- Misconfiguration Detection: Identifies common misconfigurations such as open S3 buckets, overly permissive IAM roles, and unused security groups.
- Actionable Reports: Provides a detailed, easy-to-read report with specific findings and recommended actions.
- Automated Scans: Supports both manual and scheduled scanning of AWS accounts.
- Integration with AWS SDK: Leverages AWS SDK and API calls to access account resources securely.

**Installation**
Before you can start using AWS-SecureScan, make sure you have the following:
- An AWS account with appropriate permissions to perform security checks (IAM permissions like EC2DescribeInstances, S3ListBucket, etc.).
- Python 3.x or higher installed on your machine.
- AWS CLI configured with your AWS credentials.

Install via pip

`pip install aws-securescan`

Alternatively, you can clone this repository and install the dependencies manually:

`git clone https://github.com/yourusername/aws-securescan.git`

`cd aws-securescan`

`pip install -r requirements.txt`

Run a Scan
Once AWS-SecureScan is installed, you can begin scanning your AWS account by simply running the following command:

`aws-securescan scan --profile <aws_profile> --region <aws_region>`

This will start a full security scan on your AWS environment and generate a report.

