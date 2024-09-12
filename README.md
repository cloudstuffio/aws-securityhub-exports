
# Security Hub Findings Exporter

## Description

This project allows you to deploy a solution to export and email Security Hub findings.

## Setup

All configuration occurs in the cdk.context.json.

### CDK Stack Names

```json
{
    "main_stack_name": "SecurityHubExporter",
    "event_stack_name": "Events",
    "iam_stack_name": "IAM",
    "lambda_stack_name": "Lambda"
}
```

You can have more than one rule such as a daily email and a monthly email. Each rule consists of the following:

### EventBridge Rules

Example 1: All options, daily email

```json
{
    "name": "daily-securityhub-findings",
    "from_email": "security@example.com",
    "to_emails": [
        "admin@example.com"
    ],
    "enabled": true,
    "rate": "days",
    "duration": 1,
    "subject": "Daily AWS Security Hub Findings",
    "body": "Please find the attached daily AWS Security Hub Findings export.",
    "compliance_status_filter": ["PASSED", "FAILED", "NOT_AVAILABLE", "WARNING"],
    "security_standard_filter": ["aws-foundational-security-best-practices", "aws-resource-tagging-standard", "cis-aws-foundations-benchmark", "nist-800-53", "pci-dss"],
    "severity_filter": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "workflow_status_filter": ["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"]
}
```

Example 2: All without passed, resolved, or suppressed findings, daily email

```json
{
    "name": "daily-securityhub-findings",
    "from_email": "security@example.com",
    "to_emails": [
        "admin@example.com"
    ],
    "enabled": true,
    "rate": "days",
    "duration": 1,
    "subject": "Daily AWS Security Hub Findings",
    "body": "Please find the attached daily AWS Security Hub Findings export.",
    "compliance_status_filter": ["FAILED", "NOT_AVAILABLE", "WARNING"],
    "security_standard_filter": ["aws-foundational-security-best-practices", "aws-resource-tagging-standard", "cis-aws-foundations-benchmark", "nist-800-53", "pci-dss"],
    "severity_filter": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "workflow_status_filter": ["NEW", "NOTIFIED"]
}
```

Example 3: AWS Foundational Best Practices without passed, resolved, or suppressed findings, daily email

```json
{
    "name": "daily-securityhub-findings",
    "from_email": "security@example.com",
    "to_emails": [
        "admin@example.com"
    ],
    "enabled": true,
    "rate": "days",
    "duration": 1,
    "subject": "Daily AWS Security Hub Findings",
    "body": "Please find the attached daily AWS Security Hub Findings export.",
    "compliance_status_filter": ["FAILED", "NOT_AVAILABLE", "WARNING"],
    "security_standard_filter": ["aws-foundational-security-best-practices"],
    "severity_filter": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "workflow_status_filter": ["NEW", "NOTIFIED"]
}
```

Required Arguments:

name: String for the EventBridge rule name.
from_email: String for the sent from email.
to_emails: List of strings for the send to emails.

Optional Arguments:

enabled (boolean):

- true (default)
- false

rate (string):

- minutes
- hours (default)
- days

duration (integer): 1-365 (default is 1)

subject (string): String of the subject to use for the email.

body (string): String to use for the body of the email.

compliance_status_filter (list(string)):

- PASSED
- FAILED
- NOT_AVAILABLE
- WARNING

security_standard_filter (list(string)):

- aws-foundational-security-best-practices
- aws-resource-tagging-standard
- cis-aws-foundations-benchmark
- nist-800-53
- pci-dss

severity_filter (list(string)):

- INFORMATIONAL
- LOW
- MEDIUM
- HIGH
- CRITICAL

workflow_status_filter (list(string)):

- NEW
- NOTIFIED
- RESOLVED
- SUPPRESSED

### Notes

The duration time is subject to API Rate Limits. During testing, it was found that 5 minutes was the smallest interval to use.

In AWS Simple Email Service, the domain of the emails supplied in the configuration must be verified in the SES console under Identities.

## Deploy Steps

### Prerequisites

Git
AWS CLI
AWS CDK CLI

