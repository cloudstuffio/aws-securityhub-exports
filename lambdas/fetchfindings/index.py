###############################################################################
### Imports
###############################################################################
import boto3
import json
import logging
from datetime import datetime

###############################################################################
### Boto Clients
###############################################################################
securityhub = boto3.client("securityhub")
s3 = boto3.client("s3")

###############################################################################
### Logger Instance
###############################################################################
logger = logging.getLogger()
logger.setLevel(logging.INFO)


###############################################################################
### Functions
###############################################################################
def extract_security_standards_from_finding_id(finding_id):
    """
    Extracts security standards from the findingId field.

    :param finding_id: The findingId string from which to extract the security standards.
    :return: A list of security standards found in the findingId.
    """
    known_standards = [
        "aws-foundational-security-best-practices",
        "aws-resource-tagging-standard",
        "cis-aws-foundations-benchmark",
        "nist-800-53",
        "pci-dss",
    ]
    extracted_standards = [
        standard for standard in known_standards if standard in finding_id
    ]
    return extracted_standards


def filter_data(
    input_list,
    compliance_status_filter=None,
    security_standard_filter=None,
    severity_filter=None,
    workflow_status_filter=None,
):
    """
    Filters the input list based on severity, compliance status, workflow status, and security standard, if provided,
    and flattens the structure by adding a 'workflowStatus' field. Also creates a 'securityStandards' field by examining the findingId.

    :param input_list: List of findings to filter.
    :param complianceStatus_filter: List of compliance statuses to include in the output. If None, include all.
    :param security_standard_filter: List of security standards to include in the output. If None, include all.
    :param severity_filter: List of severities to include in the output. If None, include all.
    :param workflow_status_filter: List of workflow statuses to include in the output. If None, include all.
    :return: Filtered and flattened list of findings.
    """
    logger.info("Filtering findings data")
    filtered_list = [
        {
            "awsAccountId": item.get("AwsAccountId", ""),
            "awsAccountName": item.get("AwsAccountName", ""),
            "complianceStatus": item.get("Compliance", {}).get("Status", ""),
            "controlId": item.get("ProductFields", {}).get("ControlId", ""),
            "description": item.get("Description", ""),
            "findingId": item.get("Id", ""),
            "firstSeen": item.get("FirstObservedAt", ""),
            "lastSeen": item.get("LastObservedAt", ""),
            "region": item.get("Region", ""),
            "remediationText": item.get("Remediation", {})
            .get("Recommendation", {})
            .get("Text", ""),
            "remediationUrl": item.get("Remediation", {})
            .get("Recommendation", {})
            .get("Url", ""),
            "resourceArn": item.get("Resources", [{}])[0].get("Id", ""),
            "severity": item.get("Severity", {}).get("Label", ""),
            "title": item.get("Title", ""),
            "workflowStatus": item.get("Workflow", {}).get("Status", ""),
            "securityStandards": extract_security_standards_from_finding_id(
                item.get("Id", "")
            ),
        }
        for item in input_list
        if (
            severity_filter is None
            or item.get("Severity", {}).get("Label", "") in severity_filter
        )
        and (
            compliance_status_filter is None
            or item.get("Compliance", {}).get("Status", "")
            in compliance_status_filter
        )
        and (
            workflow_status_filter is None
            or item.get("Workflow", {}).get("Status", "")
            in workflow_status_filter
        )
        and (
            security_standard_filter is None
            or any(
                standard
                in extract_security_standards_from_finding_id(
                    item.get("Id", "")
                )
                for standard in security_standard_filter
            )
        )
    ]
    logger.info(f"Filtered data contains {len(filtered_list)} findings")
    return filtered_list


def get_sh_findings(params):
    try:
        logger.info("Fetching findings from Security Hub...")
        # Fetch findings from Security Hub
        response = securityhub.get_findings(**params)
        findings = response["Findings"]
        logger.info(f"Found {len(findings)} findings")
        if "NextToken" in response:
            next_token = response["NextToken"]
            logger.info(f"New NextToken: {next_token}")
        else:
            logger.info("No NextToken found")
            next_token = None
        return findings, next_token

    except Exception as e:
        logger.error(f"Error fetching findings: {str(e)}")
        raise


def save_findings(bucket_name, findings, request_id):
    # Get current date and format it
    current_date = datetime.now().strftime("%Y-%m-%d")
    prefix = f"findings/{current_date}"
    file_name = f"part-{request_id}.json"

    try:
        logger.info(f"Saving findings to S3 bucket: {bucket_name}")
        # Upload findings to S3 (optional)
        s3.put_object(
            Bucket=bucket_name,
            Key=prefix + "/" + file_name,
            Body=json.dumps(findings),
        )
        logger.info(f"Saved findings to:")
        logger.info(f"S3 bucket: {bucket_name}")
        logger.info(f"S3 prefix: {prefix}")
        logger.info(f"File: {file_name}")

        return bucket_name, prefix
    except Exception as e:
        logger.error(f"Error saving findings to S3: {str(e)}")
        raise


###############################################################################
### Lambda Handler
###############################################################################
def lambda_handler(event, context):
    # Log Event and Context
    logger.info(f"event: {event}")
    logger.info(f"context: {context.__dict__}")

    # Get Context Request ID
    request_id = context.aws_request_id

    # Get Optional Filter Criteria
    compliance_status_filter = event.get("ComplianceStatusFilter", None)
    security_standard_filter = event.get("SecurityStandardFilter", None)
    severity_filter = event.get("SeverityFilter", None)
    workflow_status_filter = event.get("WorkflowStatusFilter", None)

    # Log Optional Filter Criteria
    logger.info(f"ComplianceStatusFilter: {compliance_status_filter}")
    logger.info(f"SecurityStandardFilter: {security_standard_filter}")
    logger.info(f"SeverityFilter: {severity_filter}")
    logger.info(f"WorkflowStatusFilter: {workflow_status_filter}")

    # Get Bucket Name
    bucket_name = event.get("BucketName", None)

    if not bucket_name:
        logger.error("BucketName is required in the event payload.")
        raise ValueError("BucketName is required in the event payload.")

    # Get NextToken
    next_token = event.get("NextToken", None)
    logger.info(f"NextToken: {next_token}")

    # Prepare Parameters
    params = {
        "MaxResults": event.get("MaxResults", 100),
    }

    # Get Security Hub Findings
    if next_token:
        logger.info(f"Fetching findings with NextToken: {next_token}")
        params["NextToken"] = next_token
        logger.info(f"Fetching findings with params: {params}")
        findings, next_token = get_sh_findings(params)
    else:
        logger.info("Fetching findings without NextToken")
        logger.info(f"Fetching findings with params: {params}")
        findings, next_token = get_sh_findings(params)

    # Filter Security Hub Findings
    filtered_data = filter_data(
        findings,
        compliance_status_filter,
        security_standard_filter,
        severity_filter,
        workflow_status_filter,
    )

    # Save Security Hub Findings to S3
    bucket_name, prefix = save_findings(bucket_name, filtered_data, request_id)

    # Prepare Response Payload
    if next_token:
        return {
            # "BucketName": bucket_name,
            "NextToken": next_token,
            "Prefix": prefix,
        }
    else:
        return {
            # "BucketName": bucket_name,
            "Prefix": prefix
        }
