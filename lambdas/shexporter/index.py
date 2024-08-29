###############################################################################
### Standard Imports
###############################################################################
import csv
import json
import logging
import os
from io import StringIO

###############################################################################
### Boto Imports
###############################################################################
import boto3
from botocore.exceptions import ClientError

###############################################################################
### Boto Clients
###############################################################################
ses = boto3.client("ses")
sh = boto3.client("securityhub")

###############################################################################
### Logger Instance
###############################################################################
logger = logging.getLogger()
logger.setLevel(logging.INFO)


###############################################################################
### Functions
###############################################################################
# def filter_data(input_list):
#     logger.info("Filtering findings data")
#     filtered_list = []
#     for item in input_list:
#         filtered_item = {
#             "awsAccountId": item.get("AwsAccountId", ""),
#             "awsAccountName": item.get("AwsAccountName", ""),
#             "controlId": item.get("ProductFields").get("ControlId", ""),
#             "description": item.get("Description", ""),
#             "findingId": item.get("Id", ""),
#             "firstSeen": item.get("FirstObservedAt", ""),
#             "lastSeen": item.get("LastObservedAt", ""),
#             "region": item.get("Region", ""),
#             "remediationText": item.get("Remediation", {})
#             .get("Recommendation", {})
#             .get("Text", ""),
#             "remediationUrl": item.get("Remediation", {})
#             .get("Recommendation", {})
#             .get("Url", ""),
#             "severity": item.get("Severity", {}).get("Label", ""),
#             "status": item.get("Compliance", {}).get("Status", ""),
#             "title": item.get("Title", ""),
#         }
#         filtered_list.append(filtered_item)
#     logger.info(f"Filtered data contains {len(filtered_list)} findings")
#     return filtered_list


# Extract Security Standards
# def extract_security_standard(types_list):
#     """
#     Extracts the last part of each string in the types list and returns the unique values.

#     :param types_list: List of strings, e.g., "Effects/Data Exposure/AWS-Foundational-Security-Best-Practices".
#     :return: A list of unique extracted values.
#     """
#     extracted_standards = set()
#     for item in types_list:
#         if "/" in item:
#             extracted_standards.add(item.split("/")[-1])
#     return list(extracted_standards)


# def filter_data(
#     input_list,
#     compliance_status_filter=None,
#     security_standard_filter=None,
#     severity_filter=None,
#     workflow_status_filter=None,
# ):
#     """
#     Filters the input list based on severity, status, and security standard, if provided.

#     :param input_list: List of findings to filter.
#     :param severity_filter: List of severities to include in the output. If None, include all.
#     :param status_filter: List of statuses to include in the output. If None, include all.
#     :param security_standard_filter: List of security standards to include in the output. If None, include all.
#     :return: Filtered list of findings.
#     """
#     logger.info("Filtering findings data")
#     filtered_list = [
#         {
#             "awsAccountId": item.get("AwsAccountId", ""),
#             "awsAccountName": item.get("AwsAccountName", ""),
#             "controlId": item.get("ProductFields", {}).get("ControlId", ""),
#             "description": item.get("Description", ""),
#             "findingId": item.get("Id", ""),
#             "firstSeen": item.get("FirstObservedAt", ""),
#             "lastSeen": item.get("LastObservedAt", ""),
#             "region": item.get("Region", ""),
#             "remediationText": item.get("Remediation", {})
#             .get("Recommendation", {})
#             .get("Text", ""),
#             "remediationUrl": item.get("Remediation", {})
#             .get("Recommendation", {})
#             .get("Url", ""),
#             "securityStandard": extract_security_standard(
#                 item.get("FindingProviderFields", {}).get("Types", [])
#             ),
#             "severity": item.get("Severity", {}).get("Label", ""),
#             "status": item.get("Compliance", {}).get("Status", ""),
#             "title": item.get("Title", ""),
#             "workflowStatus": item.get("Workflow", {}).get("Status", ""),
#         }
#         for item in input_list
#         if (
#             compliance_status_filter is None
#             or item.get("Compliance", {}).get("Status", "")
#             in compliance_status_filter
#         )
#         and (
#             security_standard_filter is None
#             or any(
#                 standard
#                 in extract_security_standard(
#                     item.get("FindingProviderFields", {}).get("Types", [])
#                 )
#                 for standard in security_standard_filter
#             )
#         )
#         and (
#             severity_filter is None
#             or item.get("Severity", {}).get("Label", "") in severity_filter
#         )
#         and (
#             workflow_status_filter is None
#             or item.get("Workflow", {}).get("Status", "")
#             in workflow_status_filter
#         )
#     ]
#     logger.info(f"Filtered data contains {len(filtered_list)} findings")
#     return filtered_list


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


def get_findings():
    logger.info("Getting findings from AWS Security Hub")
    findings = []
    try:
        paginator = sh.get_paginator("get_findings")
        for page in paginator.paginate():
            findings.extend(page["Findings"])
        logger.info(f"Found {len(findings)} findings")
        return findings
    except Exception as e:
        logger.error(f"Error getting findings: {e}")


def send_email_with_attachment(
    csv_content,
    event,
):
    logger.info("Sending email with attachment")

    # Base email attributes
    recipient_emails = event.get("to_emails")
    sender = event.get("from_email")

    # Create the email subject
    subject = event.get("subject", "AWS Security Hub Findings")

    # Create the email body
    default_text = "Please find the attached CSV file containing the filtered AWS Security Hub findings."
    body_text = event.get("body", default_text)

    # Create a new SES resource and specify a region.
    charset = event.get("charset", "utf-8")

    # Attachment Filename
    filename = event.get("filename", "securityhub_findings.csv")

    # Try to send the email
    try:
        response = ses.send_raw_email(
            Source=sender,
            Destinations=recipient_emails,
            RawMessage={
                "Data": (
                    f"From: {sender}\n"
                    f"To: {', '.join(recipient_emails)}\n"
                    f"Subject: {subject}\n"
                    "MIME-Version: 1.0\n"
                    'Content-Type: multipart/mixed; boundary="NextPart"\n\n'
                    "--NextPart\n"
                    f"Content-Type: text/plain; charset={charset}\n\n"
                    f"{body_text}\n\n"
                    "--NextPart\n"
                    "Content-Type: text/csv;\n"
                    f'Content-Disposition: attachment; filename="{filename}"\n\n'
                    f"{csv_content}\n\n"
                    "--NextPart--"
                )
            },
        )
    except ClientError as e:
        logger.error(f"Error sending email: {e.response['Error']['Message']}")
    else:
        logger.info("Email sent! Message ID:"),
        logger.info(response["MessageId"])


def write_to_csv(filtered_data):
    # Create a CSV in memory
    csv_file = StringIO()
    fieldnames = [
        "awsAccountId",
        "awsAccountName",
        "complianceStatus",
        "controlId",
        "description",
        "findingId",
        "firstSeen",
        "lastSeen",
        "region",
        "remediationText",
        "remediationUrl",
        "resourceArn",
        "securityStandards",
        "severity",
        "title",
        "workflowStatus",
    ]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    for data in filtered_data:
        writer.writerow(data)
    return csv_file.getvalue()


###############################################################################
### Lambda Handler
###############################################################################
def lambda_handler(event, context):
    # Log Event and Context
    logger.info(f"event: {event}")
    logger.info(f"context: {context.__dict__}")

    # Get Security Hub findings
    input_data = get_findings()

    # Extract filter criteria from the event data
    compliance_status_filter = event.get("compliance_status_filter", None)
    security_standard_filter = event.get("security_standard_filter", None)
    severity_filter = event.get("severity_filter", None)
    workflow_status_filter = event.get("workflow_status_filter", None)

    # Filter the data
    filtered_data = filter_data(
        input_data,
        compliance_status_filter,
        security_standard_filter,
        severity_filter,
        workflow_status_filter,
    )

    # Convert filtered data to CSV
    csv_content = write_to_csv(filtered_data)

    # Email CSV as an attachment
    recipient_emails = event.get("to_emails")
    send_email_with_attachment(
        csv_content,
        event,
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            f"Security Hub findings data has been emailed to {', '.join(recipient_emails)}"
        ),
    }
